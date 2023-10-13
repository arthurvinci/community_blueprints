//
// MIT License
//
// Copyright (c) 2023 @WeftFinance
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use scrypto::prelude::*;

#[derive(ScryptoSbor, NonFungibleData)]
pub struct FlashloanTerm {
    pub loan_amount: Decimal,
    pub fee_amount: Decimal,
}

#[derive(ScryptoSbor, PartialEq)]
pub enum WithdrawType {
    ForTemporaryUse,
    LiquidityWithdrawal,
}

#[derive(ScryptoSbor, PartialEq)]
pub enum DepositType {
    FromTemporaryUse,
    LiquidityAddition,
}

pub fn assert_fungible_res_address(address: ResourceAddress, message: Option<String>) {
    assert!(
        ResourceManager::from_address(address)
            .resource_type()
            .is_fungible(),
        "{}",
        message.unwrap_or("Resource must be fungible".to_string())
    );
}

pub fn assert_non_fungible_res_address(address: ResourceAddress, message: Option<String>) {
    assert!(
        !ResourceManager::from_address(address)
            .resource_type()
            .is_fungible(),
        "{}",
        message.unwrap_or("Resource must be non fungible".to_string())
    );
}

#[blueprint]
pub mod pool {

    enable_method_auth! {
        roles {
            admin => updatable_by: [];
        },
        methods {

            protected_deposit => restrict_to :[admin];
            protected_withdraw => restrict_to :[admin];

            decrease_external_liquidity => restrict_to :[admin];
            increase_external_liquidity => restrict_to :[admin];

            contribute => restrict_to :[admin];
            redeem  => restrict_to :[admin];

            take_flashloan => restrict_to :[admin];
            repay_flashloan => restrict_to :[admin];

            get_pool_unit_ratio => PUBLIC;
            get_pool_unit_supply => PUBLIC;
            get_pooled_amount => PUBLIC;

        }
    }

    pub struct AssetPool {
        /// Vaul containing the pooled token
        liquidity: Vault,

        /// Ammount taken from the pool and not yet returned
        external_liquidity_amount: Decimal,

        /// Flashloan term non-fungible resource manager
        flashloan_term_res_manager: ResourceManager,

        /// Pool unit fungible resource manager
        pool_unit_res_manager: ResourceManager,

        /// Ratio between the pool unit and the pooled token
        unit_to_asset_ratio: PreciseDecimal,
    }

    impl AssetPool {
        pub fn instantiate_localy(
            pool_res_address: ResourceAddress,
            owner_role: OwnerRole,
            component_rule: AccessRule,
        ) -> (Owned<AssetPool>, ResourceAddress, ResourceAddress) {
            /* CHECK INPUTS */
            assert_fungible_res_address(pool_res_address, None);

            let pool_unit_res_manager = ResourceBuilder::new_fungible(owner_role.clone())
                .mint_roles(mint_roles! {
                    minter => component_rule.clone();
                    minter_updater => rule!(deny_all);
                })
                .burn_roles(burn_roles! {
                    burner => component_rule.clone();
                    burner_updater => rule!(deny_all);
                })
                .create_with_no_initial_supply();

            let flashloan_term_res_manager =
                ResourceBuilder::new_ruid_non_fungible::<FlashloanTerm>(owner_role)
                    .mint_roles(mint_roles! {
                        minter => component_rule.clone();
                        minter_updater => rule!(deny_all);
                    })
                    .burn_roles(burn_roles! {
                        burner => component_rule.clone();
                        burner_updater => rule!(deny_all);
                    })
                    // ! critical
                    .deposit_roles(deposit_roles! {
                        depositor => rule!(deny_all);
                        depositor_updater => rule!(deny_all);
                    })
                    .create_with_no_initial_supply();

            let pool_component = Self {
                liquidity: Vault::new(pool_res_address),
                flashloan_term_res_manager,
                pool_unit_res_manager,
                external_liquidity_amount: 0.into(),
                unit_to_asset_ratio: 1.into(),
            }
            .instantiate();

            (
                pool_component,
                pool_unit_res_manager.address(),
                flashloan_term_res_manager.address(),
            )
        }

        pub fn instantiate(
            pool_res_address: ResourceAddress,
            owner_role: OwnerRole,
            admin_rule: AccessRule,
        ) -> (Global<AssetPool>, ResourceAddress, ResourceAddress) {
            /* CHECK INPUT */
            assert_fungible_res_address(pool_res_address, None);

            let (address_reservation, component_address) =
                Runtime::allocate_component_address(AssetPool::blueprint_id());

            let component_rule = rule!(require(global_caller(component_address)));

            let (owned_pool_component, pool_unit_res_manager, flashloan_term_res_manager) =
                AssetPool::instantiate_localy(pool_res_address, owner_role.clone(), component_rule);

            let pool_component = owned_pool_component
                .prepare_to_globalize(owner_role)
                .roles(roles!(
                    admin => admin_rule;
                ))
                .with_address(address_reservation)
                .globalize();

            (
                pool_component,
                pool_unit_res_manager,
                flashloan_term_res_manager,
            )
        }

        pub fn get_pool_unit_ratio(&mut self) -> PreciseDecimal {
            self.unit_to_asset_ratio
        }

        pub fn get_pool_unit_supply(&self) -> Decimal {
            self.pool_unit_res_manager.total_supply().unwrap_or(dec!(0))
        }

        pub fn get_pooled_amount(&mut self) -> (Decimal, Decimal) {
            (self.liquidity.amount(), self.external_liquidity_amount)
        }

        // Handle request to increse liquidity.
        //  Add liquidity to the pool and uand get pool units back
        pub fn contribute(&mut self, assets: Bucket) -> Bucket {
            /* CHECK INPUT */
            assert!(
                assets.resource_address() == self.liquidity.resource_address(),
                "Pool resource address mismatch"
            );

            let unit_amount = (assets.amount() * self.unit_to_asset_ratio) //
                .checked_truncate(RoundingMode::ToZero)
                .unwrap();

            self.liquidity.put(assets);

            let pool_units = self.pool_unit_res_manager.mint(unit_amount);

            pool_units
        }

        // Handle request to decrese liquidity.
        // Remove liquidity from the pool and and burn corresponding pool units
        pub fn redeem(&mut self, pool_units: Bucket) -> Bucket {
            /* INPUT CHECK */
            assert!(
                pool_units.resource_address() == self.pool_unit_res_manager.address(),
                "Pool unit resource address missmatch"
            );

            let amount = (pool_units.amount() / self.unit_to_asset_ratio) //
                .checked_truncate(RoundingMode::ToZero)
                .unwrap();

            self.pool_unit_res_manager.burn(pool_units);

            assert!(
                amount <= self.liquidity.amount(),
                "Not enough liquidity to withdraw this amount"
            );

            let assets = self
                .liquidity
                .take_advanced(amount, WithdrawStrategy::Rounded(RoundingMode::ToZero));

            assets
        }

        pub fn protected_withdraw(
            &mut self,
            amount: Decimal,
            withdraw_type: WithdrawType,
            withdraw_strategy: WithdrawStrategy,
        ) -> Bucket {
            /* INPUT CHECK */
            assert!(amount >= 0.into(), "Withdraw amount must not be negative!");

            let assets = self.liquidity.take_advanced(amount, withdraw_strategy);

            if withdraw_type == WithdrawType::ForTemporaryUse {
                self.external_liquidity_amount += amount;
            } else {
                self.unit_to_asset_ratio = self._get_unit_to_asset_ratio();
            }

            assets
        }

        pub fn protected_deposit(&mut self, assets: Bucket, deposit_type: DepositType) {
            /* INPUT CHECK */
            assert_fungible_res_address(assets.resource_address(), None);

            let amount = assets.amount();
            self.liquidity.put(assets);

            if deposit_type == DepositType::FromTemporaryUse {
                self.external_liquidity_amount -= amount;
            } else {
                self.unit_to_asset_ratio = self._get_unit_to_asset_ratio();
            }
        }

        pub fn increase_external_liquidity(&mut self, amount: Decimal) {
            assert!(
                amount >= 0.into(),
                "External liquidity amount must not be negative!"
            );

            self.external_liquidity_amount += amount;

            self.unit_to_asset_ratio = self._get_unit_to_asset_ratio();
        }

        pub fn decrease_external_liquidity(&mut self, amount: Decimal) {
            /* INPUT CHECK */
            assert!(
                amount >= 0.into(),
                "External liquidity amount must not be negative!"
            );
            assert!(
                amount <= self.external_liquidity_amount,
                "Provided amount is greater than the external liquidity amount!"
            );

            self.external_liquidity_amount -= amount;

            self.unit_to_asset_ratio = self._get_unit_to_asset_ratio();
        }

        pub fn take_flashloan(
            &mut self,
            loan_amount: Decimal,
            fee_amount: Decimal,
        ) -> (Bucket, Bucket) {
            /* INPUT CHECK */
            assert!(
                loan_amount > 0.into(),
                "Loan amount must be greater than zero!"
            );
            assert!(
                fee_amount >= 0.into(),
                "Fee amount must be greater than zero!"
            );
            assert!(
                loan_amount <= self.liquidity.amount(),
                "Not enough liquidity to supply this loan!"
            );

            // Mint the loan term. it can be deposited in any caccount so, it will need to be return with the repayment and burn for the transaction to be able to suuceed
            let loan_terms =
                self.flashloan_term_res_manager
                    .mint_ruid_non_fungible(FlashloanTerm {
                        // amount_due: fee_amount + loan_amount,
                        fee_amount,
                        loan_amount,
                    });
            (
                self.liquidity
                    .take_advanced(loan_amount, WithdrawStrategy::Rounded(RoundingMode::ToZero)),
                loan_terms,
            )
        }

        pub fn repay_flashloan(
            &mut self,
            mut loan_repayment: Bucket,
            loan_terms: Bucket,
        ) -> Bucket {
            /* INPUT CHECK */
            assert_fungible_res_address(loan_repayment.resource_address(), None);
            assert_non_fungible_res_address(loan_terms.resource_address(), None);

            // Verify we are being sent at least the amount due
            let terms: FlashloanTerm = loan_terms.as_non_fungible().non_fungible().data();
            let amount_due = terms.fee_amount + terms.loan_amount;
            assert!(
                loan_repayment.amount() >= amount_due,
                "Insufficient repayment given for your loan!"
            );

            // put the repayment back into the pool
            self.liquidity.put(
                loan_repayment
                    .take_advanced(amount_due, WithdrawStrategy::Rounded(RoundingMode::ToZero)),
            );

            //Burn the transient token
            loan_terms.burn();

            //Return the change to the work top
            loan_repayment
        }

        /* PRIVATE UTILITY METHODS */

        fn _get_unit_to_asset_ratio(&mut self) -> PreciseDecimal {
            let total_liquidity_amount = self.liquidity.amount() + self.external_liquidity_amount;

            let total_supply = self.pool_unit_res_manager.total_supply().unwrap_or(dec!(0));

            let ratio = if total_liquidity_amount != 0.into() {
                PreciseDecimal::from(total_supply) / PreciseDecimal::from(total_liquidity_amount)
            } else {
                1.into()
            };

            ratio
        }
    }
}

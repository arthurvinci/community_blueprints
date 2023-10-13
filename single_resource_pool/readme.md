# SingleResourcePool: Radix OneResourcePool with Additional Features

The primary objective of Radix native pools is to offer a seamless approach for creating a resource pool that can be leveraged by multiple applications. 
We encourage developers to use the native pools as a starting point for their projects. However, we also understand that the native pools might not be suitable for all use cases.
With SingleResourcePool, we aim to include some extra features, making it adaptable to some of the more specific use cases.

## Additional Features

### 1. External Liquidity Accommodation

One of the key enhancements in this implementation is the accommodation of resources that temporarily exist outside the pool. While this might seem unconventional, it can be highly beneficial in scenarios like lending and market-making. Resources temporarily outside the pool can be employed for specific purposes, such as loans, and then seamlessly reintegrated into the pool when their usage is complete. This feature extends the flexibility of the SingleResourcePool.

### 2. Flash Loan Activation

The second feature is the ability to activate flash loans. This feature is particularly valuable when you intend to use the pool as a provider of flash loans, a concept prevalent in DeFi. By enabling this feature, you can generate additional revenue for liquidity providers. This showcases the versatility of the SingleResourcePool in DeFi applications.

## Implementation

Incorporating these features into the SingleResourcePool was a relatively straightforward process. Here's a brief overview of how they work:

- **External Liquidity Accommodation**: This feature introduces an 'external_liquidity_amount' variable that tracks the amount of liquidity being utilized outside the pool. Additionally, a set of methods has been implemented to help keep this variable updated. The 'external_liquidity_amount' plays a pivotal role in the calculation of pool units, ensuring accurate accounting for the external resources.

- **Flash Loan Activation**: The implementation of flash loans is derived from an official example. Enabling this feature allows the pool to participate in providing flash loans, potentially opening up new revenue streams for liquidity providers.

## Usage

To be written (TBW).

## Contributing

We would love to have feedback and contributions from the community. Feel free to open issues, create pull requests, or just join the discussions.

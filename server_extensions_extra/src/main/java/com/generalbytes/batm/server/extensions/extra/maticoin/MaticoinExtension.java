package com.generalbytes.batm.server.extensions.extra.maticoin;

import com.generalbytes.batm.common.currencies.CryptoCurrency;
import com.generalbytes.batm.common.currencies.FiatCurrency;
import com.generalbytes.batm.server.extensions.*;
import com.generalbytes.batm.server.extensions.extra.ethereum.InfuraWallet;
import com.generalbytes.batm.server.extensions.extra.ethereum.erc20.ERC20Wallet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

public class MaticoinExtension extends AbstractExtension {

    private static final Logger log = LoggerFactory.getLogger(MaticoinExtension.class);

    @Override
    public String getName() {
        return "BATM Maticoin extension";
    }

    @Override
    public Set<String> getSupportedCryptoCurrencies() {
        Set<String> result = new HashSet<String>();
        result.add(CryptoCurrency.MCOIN.getCode());
        return result;
    }

    @Override
    public IWallet createWallet(String walletLogin, String tunnelPassword) {
        if (walletLogin != null && !walletLogin.trim().isEmpty()) {
            try {
                StringTokenizer st = new StringTokenizer(walletLogin,":");
                String walletType = st.nextToken();

                if ("polygon".equalsIgnoreCase(walletType)) {
                    String projectId = st.nextToken();
                    String passwordOrMnemonic = st.nextToken();
                    if (projectId != null && passwordOrMnemonic != null) {
                        return new InfuraWallet(projectId, passwordOrMnemonic);
                    }
                } else if (walletType.startsWith("polygonERC20_")) {
                    StringTokenizer wt = new StringTokenizer(walletType,"_");
                    wt.nextToken();
                    String tokenSymbol = wt.nextToken();
                    int tokenDecimalPlaces = Integer.parseInt(wt.nextToken());
                    String contractAddress = wt.nextToken();

                    String projectId = st.nextToken();
                    String passwordOrMnemonic = st.nextToken();
                    BigInteger gasLimit = null;
                    if (st.hasMoreTokens()) {
                        gasLimit = new BigInteger(st.nextToken());
                    }
                    BigDecimal gasPriceMultiplier = BigDecimal.ONE;
                    if (st.hasMoreTokens()) {
                        gasPriceMultiplier = new BigDecimal(st.nextToken());
                    }

                    if (projectId != null && passwordOrMnemonic != null) {
                        return new ERC20Wallet(projectId, passwordOrMnemonic, tokenSymbol, tokenDecimalPlaces, contractAddress, gasLimit, gasPriceMultiplier);
                    }
                }
            } catch (Exception e) {
                log.warn("createWallet failed for prefix: {}, {}: {}",
                    ExtensionsUtil.getPrefixWithCountOfParameters(walletLogin), e.getClass().getSimpleName(), e.getMessage()
                );
            }
        }
        return null;
    }

    @Override
    public ICryptoAddressValidator createAddressValidator(String cryptoCurrency) {
        if (CryptoCurrency.MCOIN.getCode().equalsIgnoreCase(cryptoCurrency)) {
            return new MaticoinAddressValidator();
        }
        return null;
    }

    @Override
    public IRateSource createRateSource(String sourceLogin) {
        if (sourceLogin != null && !sourceLogin.trim().isEmpty()) {
            try {
                StringTokenizer st = new StringTokenizer(sourceLogin, ":");
                String exchangeType = st.nextToken();

                if ("mcoinfix".equalsIgnoreCase(exchangeType)) {
                    BigDecimal rate = BigDecimal.ZERO;
                    if (st.hasMoreTokens()) {
                        try {
                            rate = new BigDecimal(st.nextToken());
                        } catch (Throwable e) {
                        }
                    }
                    String preferedFiatCurrency = FiatCurrency.USD.getCode();
                    if (st.hasMoreTokens()) {
                        preferedFiatCurrency = st.nextToken().toUpperCase();
                    }
                    return new FixPriceRateSource(rate, preferedFiatCurrency);
                }
            } catch (Exception e) {
                log.warn("createRateSource failed for prefix: {}, {}: {} ",
                    ExtensionsUtil.getPrefixWithCountOfParameters(sourceLogin), e.getClass().getSimpleName(), e.getMessage()
                );
            }

        }
        return null;
    }

}

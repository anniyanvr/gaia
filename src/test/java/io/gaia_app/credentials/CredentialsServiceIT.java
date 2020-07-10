package io.gaia_app.credentials;

import org.checkerframework.checker.units.qual.A;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultMount;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.vault.VaultContainer;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {"gaia.vault.enable=true",
    "gaia.vault.authentication.token=admin123",
    "gaia.vault.uri=http://localhost:8200"})
@Testcontainers
public class CredentialsServiceIT {

    @Container
    private static final VaultContainer vaultContainer = new VaultContainer();

    @Autowired
    private CredentialsService credentialsService;

    @Autowired
    private VaultTemplate vaultTemplate;

    @BeforeEach
    void setUp() {
        // recreating transit secret engine
        vaultTemplate.opsForSys().unmount("transit");
        vaultTemplate.opsForSys().mount("transit", VaultMount.builder().type("transit").build());
    }

    @Test
    void contextLoads() {
        assertThat(credentialsService).isNotNull();
        assertThat(vaultTemplate).isNotNull();
    }

    @Test
    void testEncryption(){
        var awsCredentials = new AWSCredentials("accesskey", "secretKey");

        var encrypted = credentialsService.encrypt(awsCredentials);

        assertThat(encrypted.getAccessKey()).isNotEqualTo("accesskey");
        assertThat(encrypted.getSecretKey()).isNotEqualTo("secretKey");
    }

}


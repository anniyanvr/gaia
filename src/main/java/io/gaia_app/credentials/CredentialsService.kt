package io.gaia_app.credentials

import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.stereotype.Service
import org.springframework.vault.core.VaultTemplate
import java.util.*

@Service
class CredentialsService(val credentialsRepository: CredentialsRepository){

    @Autowired(required = false)
    lateinit var vaultTemplate:VaultTemplate

    fun loadCredentials(id: String): Credentials {
        return when(val credentials = this.credentialsRepository.findById(id).orElseThrow()) {
            is VaultAWSCredentials -> loadAWSCredentialsFromVault(credentials)
            else -> credentials
        }
    }

    fun loadAWSCredentialsFromVault(vaultAWSCredentials: VaultAWSCredentials): AWSCredentials {
        val path = "${vaultAWSCredentials.vaultAwsSecretEnginePath.trimEnd('/')}/creds/${vaultAWSCredentials.vaultAwsRole}"
        val vaultResponse = vaultTemplate.read(path, VaultAWSResponse::class.java)

        // IAM credentials are eventually consistent with respect to other Amazon services.
        // adding a delay of 5 seconds before returning them
        runBlocking {
            delay(5_000)
        }

        return vaultResponse?.data?.toAWSCredentials() ?: throw RuntimeException("boum vault")
    }

    fun encrypt(awsCredentials: AWSCredentials): AWSCredentials {
        // encrypting access key & secret
        val accessKeyBase64 = Base64.getEncoder().encodeToString(awsCredentials.accessKey.toByteArray())
        val secretKeyBase64 = Base64.getEncoder().encodeToString(awsCredentials.secretKey.toByteArray())

        val toEncrypt = BatchTransitRequest(listOf(TransitRequest(accessKeyBase64), TransitRequest(secretKeyBase64)))

        val response = vaultTemplate.write("transit/encrypt/gaia_key", toEncrypt)

        // getting encrypted values in response
        val responseResults = response.data["batch_results"] as List<Map<String, String>>

        val encryptedAccessKey = responseResults[0]["ciphertext"]!!
        val encryptedSecretKey = responseResults[1]["ciphertext"]!!

        return AWSCredentials(encryptedAccessKey, encryptedSecretKey)
    }

}

data class VaultAWSResponse(val access_key: String, val secret_key: String){
    fun toAWSCredentials() = AWSCredentials(access_key, secret_key)
}

data class BatchTransitRequest(val batch_input: List<TransitRequest>)

data class TransitRequest(val plainttext: String)

package cliente;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class clienteFunctions {

    private String algoritmo_asimetrico = "RSA";
    private String algoritmo_simetrico = "AES/CBC/PKCS5Padding";
    private String algoritmo_hash = "SHA-256";
    private String algoritmo_mac = "HMACSHA256";
    private String algoritmo_firma = "SHA256withRSA";

    public byte[] sign(PrivateKey privada, String mensaje) throws Exception {
        Signature privateSignature = Signature.getInstance(algoritmo_firma);
        privateSignature.initSign(privada);
        privateSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        byte[] signature = privateSignature.sign();
        return signature;
    }

    public boolean checkSignature(PublicKey publica, byte[] firma, String mensaje) throws Exception {
        Signature publicSignature = Signature.getInstance(algoritmo_firma);
        publicSignature.initVerify(publica);
        publicSignature.update(mensaje.getBytes(StandardCharsets.UTF_8));
        boolean isCorrect = publicSignature.verify(firma);
        return isCorrect;
    }

}

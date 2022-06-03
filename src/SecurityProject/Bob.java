
package SecurityProject;

import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Bob {

    KeyPair Bob_RSAKeys;
    Key AES_SecretKey;
    PublicKey AlicePU;

    public void generateKeys() throws NoSuchAlgorithmException {
        // Generate AES Secret Key 
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        int KeySize = 128;
        kg.init(KeySize); // AES key can be 128, 192, or 256
        AES_SecretKey = kg.generateKey();

        // Generate RSA Pair Keys
        KeyPairGenerator generatePairKey = KeyPairGenerator.getInstance("RSA");
        Bob_RSAKeys = generatePairKey.generateKeyPair();
    }

    public void setAES_SecretKey(Key EncryptedKey) throws Exception {

        // Decrypt The Key Using RSA Cipher & Bob Private Key
        Cipher RSA_cipher = Cipher.getInstance("RSA");
        byte[] KeyBytes = EncryptedKey.getEncoded();
        RSA_cipher.init(Cipher.DECRYPT_MODE, Bob_RSAKeys.getPrivate());
        byte[] RSA_KeyDecryptedBytes = RSA_cipher.doFinal(KeyBytes);
        // Get Decrypted AES Key Using SecretKeySpec Class Constructor "Polymorphism "
        this.AES_SecretKey = new SecretKeySpec(RSA_KeyDecryptedBytes, 0, RSA_KeyDecryptedBytes.length, "AES");
    }

    public PublicKey getBobPU() {
        return Bob_RSAKeys.getPublic();
    }

    public void setAlicePU(PublicKey AlicePU) {
        this.AlicePU = AlicePU;
    }
    
    public void reciveMessage(String EncryptedMessage) throws Exception {

        // Create ASE Cipher
        Cipher ASE_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // if we write 'NOPADDING', then the message SHOULD be a multiple of 16 bytes

        // Create initialization vector 
        IvParameterSpec IV = new IvParameterSpec(new byte[16]);

        // Convert the Message from String to Message Bytes
        byte[] MessageBytes = Base64.getDecoder().decode(EncryptedMessage);

        // Start Decrypt the Message
        ASE_cipher.init(Cipher.DECRYPT_MODE, AES_SecretKey, IV);
        byte[] AES_DecryptedBytes = ASE_cipher.doFinal(MessageBytes);

        // Convert Decrypted Bytes to String
        String Decrypted_Message = new String(AES_DecryptedBytes);

        // Decrypt Message
        System.out.println("Alice Message to Bob : " + Decrypted_Message);

    }
    
        public String sendMessage() throws Exception {

        // get text message from the user
        System.out.print("Enter Your Message : ");
        Scanner scan = new Scanner(System.in);
        String message = scan.nextLine();
        // convert message to array of bytes
        byte[] ByteMessage = message.getBytes();

        // Create initialization vector "use for padding"
        IvParameterSpec IV = new IvParameterSpec(new byte[16]);

        // Encrypt Message 
        Cipher ASE_cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ASE_cipher.init(Cipher.ENCRYPT_MODE, AES_SecretKey, IV);
        byte[] AES_EncryptedBytes = ASE_cipher.doFinal(ByteMessage);

        // convert encrypted bytes to string and return it
        String Encryotedmessage = Base64.getEncoder().encodeToString(AES_EncryptedBytes);
        System.out.println("Bob Encrypted Message : "+ Encryotedmessage );
        return Encryotedmessage;

    }

    public Key getSecretKey() throws Exception {
        
        // Encrypt Secret Key Using RSA & Bob Public Key 
        Cipher RSA_cipher = Cipher.getInstance("RSA");
        RSA_cipher.init(Cipher.ENCRYPT_MODE, AlicePU);
        
        // Convert The Secret Key to Byte[]
        byte[] KeyBytes = AES_SecretKey.getEncoded();
        byte[] RSA_KeyEncryptedBytes = RSA_cipher.doFinal(KeyBytes);
        
        // Convert the Encrypted Key Array Bytes to Key Object 
        Key encryptedKey = new SecretKeySpec(RSA_KeyEncryptedBytes, 0, RSA_KeyEncryptedBytes.length, "AES");
        
        return encryptedKey;
    }
  
    

}

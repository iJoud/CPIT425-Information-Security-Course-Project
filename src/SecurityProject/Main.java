package SecurityProject;


import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class Main {

    public static void main(String[] args) throws Exception {


    Alice alice = new Alice();
    Bob bob = new Bob();
    
    // let Alice and Bob both generate their keys
    alice.generateKeys();
    bob.generateKeys();
    
    // Alice will send a mesaage to bob, so Bob's Public Key is required to encrypt the secret key
    alice.setBobPU(bob.getBobPU());

    // Bob recive the encrepted secret key from alice,
    // Bob should decrypt the secret key using his private key
    bob.setAES_SecretKey(alice.getSecretKey());
    
    // bob recive encrypted message from alice 
    bob.reciveMessage( alice.sendMessage() );

    
    }

}

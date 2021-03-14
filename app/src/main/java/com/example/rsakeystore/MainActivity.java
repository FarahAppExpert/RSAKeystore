package com.example.rsakeystore;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
import java.math.BigInteger;
import java.util.Map;



public class MainActivity extends AppCompatActivity
{
   private EditText Input;
   private EditText Output;
   private String privateKey = "";
   private String publicKey = "";
   private byte[] decodeData = null;
   private byte[] encodeData = null;

    @Override
    protected void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Input = findViewById(R.id.input);
        Output = findViewById(R.id.output);


        try {
           Map<String, Object> stringObjectMap = RSA.initKey();
           publicKey = RSA.getPublicKey(stringObjectMap);
           privateKey = RSA.getPrivateKey(stringObjectMap);
        }
        catch (Exception exception)
        {
            exception.printStackTrace();
        }


    }

    public void Encryption (View view)
    {
      String  publicKey = getPublicKey();
      byte[] InputRSA = Input.getText().toString().getBytes();

      try {

          encodeData = RSA.encryptByPublicKey(InputRSA, publicKey);
          String encodeString = new BigInteger(1, encodeData).toString();
          Output.setText(encodeString);
      }
      catch (Exception exception)
      {
          exception.printStackTrace();
      }

    }

    public void Decryption (View view)
    {
      String privateKey = getPrivateKey();
      byte[] InputRSA = Input.getText().toString().getBytes();

      try
      {
          decodeData = RSA.encryptByPrivateKey(InputRSA, privateKey);
          String decodeString = new BigInteger(1, decodeData).toString();
          Output.setText(decodeString);

      } catch (Exception exception)
      {
          exception.printStackTrace();
      }
    }

    public String getPrivateKey() {
        return privateKey;
    }


    public String getPublicKey() {
        return publicKey;
    }


}

package com.example.registration;

import androidx.appcompat.app.AppCompatActivity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import android.os.Bundle;

public class MainActivity extends AppCompatActivity {
    private EditText username,email,passwd;
    private Button regbtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        username=findViewById(R.id.usernameText);
        email=findViewById(R.id.emailText);
        passwd=findViewById(R.id.passwordText);
        regbtn=findViewById(R.id.registerButton);

        regbtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String uname=username.getText().toString();
                String em=email.getText().toString();
                String pwd=passwd.getText().toString();

                SharedPreferences preferences=getSharedPreferences("MyPref",MODE_PRIVATE);
                SharedPreferences.Editor editor=preferences.edit();
                editor.putString("username",uname);
                editor.putString("email",em);
                editor.putString("password",pwd);
                editor.apply();

                Toast.makeText(MainActivity.this,"Registration successfull",Toast.LENGTH_SHORT).show();

                Intent intent=new Intent(MainActivity.this,MainActivity.class);
                startActivity(intent);
            }
        });


    }
}

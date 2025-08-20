package com.example.ui_control;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;



public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button constraintButton=findViewById(R.id.constraintButton);
        Button linearButton=findViewById(R.id.linearButton);
        Button gridButton=findViewById(R.id.gridButton);
        Button relativeButton=findViewById(R.id.relativeButton);
        Button frameButton=findViewById(R.id.frameButton);
        Button tableButton=findViewById(R.id.tableButton);

        View.OnClickListener buttonClickListener=new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                String layoutName=((Button) view).getText().toString();
                displayToken(layoutName);
            }
        };
        constraintButton.setOnClickListener(buttonClickListener);
        linearButton.setOnClickListener(buttonClickListener);
        gridButton.setOnClickListener(buttonClickListener);
        relativeButton.setOnClickListener(buttonClickListener);
        frameButton.setOnClickListener(buttonClickListener);
        tableButton.setOnClickListener(buttonClickListener);
    }
    private void displayToken(String layoutName){
        Toast.makeText(this,"Token from"+layoutName,Toast.LENGTH_SHORT).show();
    }
}
package com.example.lifecycle;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.Button;
import android.widget.Toast;
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        showToast("Activity Created");

        Button onCreateButton=findViewById(R.id.onCreateButton);
        Button onStartButton=findViewById(R.id.onStartButton);
        Button onPauseButton=findViewById(R.id.onPauseButton);
        Button onStopButton=findViewById(R.id.onStopButton);
        Button onRestartButton=findViewById(R.id.onRestartButton);
        Button onDestroyButton=findViewById(R.id.onDestroyButton);

        onCreateButton.setOnClickListener(v->showToast("onCreate() Clicked"));
        onStartButton.setOnClickListener(v->showToast("onStrat() Clicked"));
        onPauseButton.setOnClickListener(v->showToast("onPause() Clicked"));
        onStopButton.setOnClickListener(v->showToast("onStoop() Clicked"));
        onRestartButton.setOnClickListener(v->showToast("onRestart() Clicked"));
        onDestroyButton.setOnClickListener(v->showToast("onDestroy() Clicked"));

    }
    @Override
    protected void onStart(){
        super.onStart();
        showToast("Activity Started");
    }
    @Override
    protected void onResume(){
        super.onResume();
        showToast("Activity Resumed");
    }
    @Override
    protected void onPause(){
        super.onPause();
        showToast("Activity Paused");
    }
    @Override
    protected void onStop(){
        super.onStop();
        showToast("Activity Stoped");
    }
    @Override
    protected void onRestart(){
        super.onRestart();
        showToast("Activity Restarted");
    }
    @Override
    protected void onDestroy(){
        super.onDestroy();
        showToast("Activity Destroyed");
    }
    void showToast(String message){
        Toast.makeText(this,message,Toast.LENGTH_SHORT).show();
    }
}
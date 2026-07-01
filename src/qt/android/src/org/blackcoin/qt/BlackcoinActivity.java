package org.blackcoin.qt;

import android.os.Bundle;
import android.system.ErrnoException;
import android.system.Os;

import org.qtproject.qt5.android.bindings.QtActivity;

import java.io.File;

public class BlackcoinActivity extends QtActivity
{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        final File dataDir = new File(getFilesDir().getAbsolutePath() + "/.blackcoin");
        if (!dataDir.exists()) {
            dataDir.mkdir();
        }

        super.onCreate(savedInstanceState);
    }
}

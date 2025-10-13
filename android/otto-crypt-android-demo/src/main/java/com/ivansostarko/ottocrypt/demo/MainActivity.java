package com.ivansostarko.ottocrypt.demo;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.viewpager2.widget.ViewPager2;
import com.google.android.material.tabs.TabLayout;
import com.google.android.material.tabs.TabLayoutMediator;

public class MainActivity extends AppCompatActivity {
    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        TabLayout tabs = findViewById(R.id.tabLayout);
        ViewPager2 pager = findViewById(R.id.viewPager);
        pager.setAdapter(new PagerAdapter(this));
        new TabLayoutMediator(tabs, pager, (tab, pos) -> tab.setText(pos==0?"Text":"Files")).attach();
    }
}

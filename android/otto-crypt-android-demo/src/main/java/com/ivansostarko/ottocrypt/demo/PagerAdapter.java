package com.ivansostarko.ottocrypt.demo;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.viewpager2.adapter.FragmentStateAdapter;

public class PagerAdapter extends FragmentStateAdapter {
    public PagerAdapter(@NonNull FragmentActivity fa){ super(fa); }
    @NonNull @Override public Fragment createFragment(int position) {
        return position==0? new TextFragment(): new FilesFragment();
    }
    @Override public int getItemCount(){ return 2; }
}

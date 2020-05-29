package com.biapp.room;

import androidx.room.Entity;
import androidx.room.PrimaryKey;

import org.parceler.Parcel;

/**
 * @author yun
 */
@Entity
@Parcel
public class BIApp {
    @PrimaryKey(autoGenerate = true)
    /***
     * 主键自增长
     */
    public int uid;
}

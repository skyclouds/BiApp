package com.biapp.room;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;
import androidx.room.migration.Migration;
import androidx.sqlite.db.SupportSQLiteDatabase;


/**
 * @author Yun
 */
@Database(entities = {BIApp.class}, version = 1, exportSchema = false)
public abstract class AppDatabase extends RoomDatabase {

    public abstract BIAppDao biAppDao();

    public abstract RxBIAppDao rxBIAppDao();

    /**
     * Database name.
     */
    public static String DATABASE_NAME = "biapp_db";

    /**
     * Database instance;
     */
    private static AppDatabase instance;

    /**
     * Get default database instance.
     *
     * @return
     */
    public static AppDatabase getDefault() {
        if (instance == null) {
            throw new IllegalStateException("Please initialize database first.");
        }

        return instance;
    }

    /**
     * Init database.
     *
     * @param context
     */
    public static void init(Context context) {
        Builder<AppDatabase> builder = Room.databaseBuilder(context.getApplicationContext(),
                AppDatabase.class, DATABASE_NAME)
                // Add all migrations here.
                //
                // When there is update and the table schema has changed,
                // You just care bout the changes between the current version and the last version.
                //
                // Every upgrade with table schema should have a Migration object to be added.
                .addMigrations(new Migration(1, 2) {
                    @Override
                    public void migrate(@NonNull SupportSQLiteDatabase database) {

                    }
                });

        // 如果调试模式，当表结构发生变化时，允许清空数据，重建表结构
        // For debug, allow to clear the data and recreate the tables.
        if (BuildConfig.DEBUG) {
            builder = builder.fallbackToDestructiveMigration();
        }

        instance = builder.build();
    }
}
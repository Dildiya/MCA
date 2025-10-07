package com.example.sqlite;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import androidx.annotation.Nullable;
public class DatabaseHelper extends SQLiteOpenHelper {

    private static final String DATABASE_NAME = "Student.db";
    private static final int DATABASE_VERSION = 1;

    private static final String TABLE_NAME = "student_table";
    public static final String COL_1 = "ID";
    public static final String COL_2 = "NAME";
    public static final String COL_3 = "EMAIL";

    public DatabaseHelper(@Nullable Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }
    // This method is called when the database is created for the first time.
    @Override
    public void onCreate(SQLiteDatabase db) {

        String CREATE_TABLE = "CREATE TABLE " + TABLE_NAME + " (" +
                COL_1 + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COL_2 + " TEXT, " +
                COL_3 + " TEXT)";
        db.execSQL(CREATE_TABLE);
    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
// Drop the old table if it exists
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME);
// Create a new one
        onCreate(db);
    }
    // Method to insert a new record (CREATE operation)
    public boolean insertData(String name, String email) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(COL_2, name);
        contentValues.put(COL_3, email);
// The insert() method returns the row ID of the newly inserted row, or -1 if an error occurred
        long result = db.insert(TABLE_NAME, null, contentValues);
        return result != -1;
    }
    // Method to get all records from the database (READ operation)
    public Cursor getAllData() {
        SQLiteDatabase db = this.getReadableDatabase();
// The rawQuery() method executes a raw SQL query and returns a Cursor
        Cursor res = db.rawQuery("SELECT * FROM " + TABLE_NAME, null);
        return res;
    }
    // Method to update an existing record (UPDATE operation)
    public boolean updateData(String id, String name, String email) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put(COL_1, id);
        contentValues.put(COL_2, name);
        contentValues.put(COL_3, email);
// The update() method returns the number of rows affected
        db.update(TABLE_NAME, contentValues, "ID = ?", new String[]{id});
        return true;
    }
    // Method to delete a record (DELETE operation)
    public Integer deleteData(String id) {
        SQLiteDatabase db = this.getWritableDatabase();
// The delete() method returns the number of rows affected
        return db.delete(TABLE_NAME, "ID = ?", new String[]{id});
    }
}
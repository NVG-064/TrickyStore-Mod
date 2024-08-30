/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.security.keymaster;

import android.os.Parcel;
import android.os.Parcelable;

import androidx.annotation.NonNull;

import java.math.BigInteger;
import java.util.Date;
import java.util.List;

/**
 * Utility class for the java side of user specified Keymaster arguments.
 * <p>
 * Serialization code for this and subclasses must be kept in sync with system/security/keystore
 * @hide
 */
public class KeymasterArguments implements Parcelable {

    private static final long UINT32_RANGE = 1L << 32;
    public static final long UINT32_MAX_VALUE = UINT32_RANGE - 1;

    private static final BigInteger UINT64_RANGE = BigInteger.ONE.shiftLeft(64);
    public static final BigInteger UINT64_MAX_VALUE = UINT64_RANGE.subtract(BigInteger.ONE);

    private List<KeymasterArgument> mArguments;

    public static final @NonNull Parcelable.Creator<KeymasterArguments> CREATOR = new
            Parcelable.Creator<KeymasterArguments>() {
                @Override
                public KeymasterArguments createFromParcel(Parcel in) {
                    throw new RuntimeException("");
                }

                @Override
                public KeymasterArguments[] newArray(int size) {
                    throw new RuntimeException("");
                }
            };

    public KeymasterArguments() {
        throw new RuntimeException("");
    }

    private KeymasterArguments(Parcel in) {
        throw new RuntimeException("");
    }

    /**
     * Adds an enum tag with the provided value.
     *
     * @throws IllegalArgumentException if {@code tag} is not an enum tag.
     */
    public void addEnum(int tag, int value) {
        throw new RuntimeException("");
    }

    /**
     * Adds a repeated enum tag with the provided values.
     *
     * @throws IllegalArgumentException if {@code tag} is not a repeating enum tag.
     */
    public void addEnums(int tag, int... values) {
        throw new RuntimeException("");
    }

    /**
     * Returns the value of the specified enum tag or {@code defaultValue} if the tag is not
     * present.
     *
     * @throws IllegalArgumentException if {@code tag} is not an enum tag.
     */
    public int getEnum(int tag, int defaultValue) {
        throw new RuntimeException("");
    }

    /**
     * Returns all values of the specified repeating enum tag.
     *
     * throws IllegalArgumentException if {@code tag} is not a repeating enum tag.
     */
    public List<Integer> getEnums(int tag) {
        throw new RuntimeException("");
    }

    private void addEnumTag(int tag, int value) {
        throw new RuntimeException("");
    }

    private int getEnumTagValue(KeymasterArgument arg) {
        throw new RuntimeException("");
    }

    /**
     * Adds an unsigned 32-bit int tag with the provided value.
     *
     * @throws IllegalArgumentException if {@code tag} is not an unsigned 32-bit int tag or if
     *         {@code value} is outside of the permitted range [0; 2^32).
     */
    public void addUnsignedInt(int tag, long value) {
        throw new RuntimeException("");
    }

    /**
     * Returns the value of the specified unsigned 32-bit int tag or {@code defaultValue} if the tag
     * is not present.
     *
     * @throws IllegalArgumentException if {@code tag} is not an unsigned 32-bit int tag.
     */
    public long getUnsignedInt(int tag, long defaultValue) {
        throw new RuntimeException("");
    }

    /**
     * Adds an unsigned 64-bit long tag with the provided value.
     *
     * @throws IllegalArgumentException if {@code tag} is not an unsigned 64-bit long tag or if
     *         {@code value} is outside of the permitted range [0; 2^64).
     */
    public void addUnsignedLong(int tag, BigInteger value) {
        throw new RuntimeException("");
    }

    /**
     * Returns all values of the specified repeating unsigned 64-bit long tag.
     *
     * @throws IllegalArgumentException if {@code tag} is not a repeating unsigned 64-bit long tag.
     */
    public List<BigInteger> getUnsignedLongs(int tag) {
        throw new RuntimeException("");
    }

    private void addLongTag(int tag, BigInteger value) {
        throw new RuntimeException("");
    }

    private BigInteger getLongTagValue(KeymasterArgument arg) {
        throw new RuntimeException("");
    }

    /**
     * Adds the provided boolean tag. Boolean tags are considered to be set to {@code true} if
     * present and {@code false} if absent.
     *
     * @throws IllegalArgumentException if {@code tag} is not a boolean tag.
     */
    public void addBoolean(int tag) {
        throw new RuntimeException("");
    }

    /**
     * Returns {@code true} if the provided boolean tag is present, {@code false} if absent.
     *
     * @throws IllegalArgumentException if {@code tag} is not a boolean tag.
     */
    public boolean getBoolean(int tag) {
        throw new RuntimeException("");
    }

    /**
     * Adds a bytes tag with the provided value.
     *
     * @throws IllegalArgumentException if {@code tag} is not a bytes tag.
     */
    public void addBytes(int tag, byte[] value) {
        throw new RuntimeException("");
    }

    /**
     * Returns the value of the specified bytes tag or {@code defaultValue} if the tag is not
     * present.
     *
     * @throws IllegalArgumentException if {@code tag} is not a bytes tag.
     */
    public byte[] getBytes(int tag, byte[] defaultValue) {
        throw new RuntimeException("");
    }

    /**
     * Adds a date tag with the provided value.
     *
     * @throws IllegalArgumentException if {@code tag} is not a date tag or if {@code value} is
     *         before the start of Unix epoch.
     */
    public void addDate(int tag, Date value) {
        throw new RuntimeException("");
    }

    /**
     * Adds a date tag with the provided value, if the value is not {@code null}. Does nothing if
     * the {@code value} is null.
     *
     * @throws IllegalArgumentException if {@code tag} is not a date tag or if {@code value} is
     *         before the start of Unix epoch.
     */
    public void addDateIfNotNull(int tag, Date value) {
        throw new RuntimeException("");
    }

    /**
     * Returns the value of the specified date tag or {@code defaultValue} if the tag is not
     * present.
     *
     * @throws IllegalArgumentException if {@code tag} is not a date tag or if the tag's value
     *         represents a time instant which is after {@code 2^63 - 1} milliseconds since Unix
     *         epoch.
     */
    public Date getDate(int tag, Date defaultValue) {
        throw new RuntimeException("");
    }

    private KeymasterArgument getArgumentByTag(int tag) {
        throw new RuntimeException("");
    }

    public boolean containsTag(int tag) {
        throw new RuntimeException("");
    }

    public int size() {
        throw new RuntimeException("");
    }

    @Override
    public void writeToParcel(Parcel out, int flags) {
        throw new RuntimeException("");
    }

    public void readFromParcel(Parcel in) {
        throw new RuntimeException("");
    }

    @Override
    public int describeContents() {
        throw new RuntimeException("");
    }

    /**
     * Converts the provided value to non-negative {@link BigInteger}, treating the sign bit of the
     * provided value as the most significant bit of the result.
     */
    public static BigInteger toUint64(long value) {
        throw new RuntimeException("");
    }
}
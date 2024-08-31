package io.github.a13e300.tricky_store.keystore;

import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class Utils {
    private final static String TAG = "Utils";
    public static X509Certificate toCertificate(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificate in keystore", e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public static Collection<X509Certificate> toCertificates(byte[] bytes) {
        try {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (Collection<X509Certificate>) certFactory.generateCertificates(
                    new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            Log.w(TAG, "Couldn't parse certificates in keystore", e);
            return new ArrayList<>();
        }
    }

    public static byte[] toBytes(Collection<Certificate> certificates) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            for (Certificate cert : certificates) {
                byteArrayOutputStream.write(cert.getEncoded());
            }
            return byteArrayOutputStream.toByteArray();
        } catch (Exception e) {
            Log.w(TAG, "Couldn't getBytes certificates in keystore", e);
            return null;
        }
    }
    public static List<byte[]> toListBytes(Collection<Certificate> certificates) {
        try {
            List<byte[]> chain = new ArrayList<>();
            for (Certificate cert : certificates) {
                chain.add(cert.getEncoded());
            }
            return chain;
        } catch (Exception e) {
            Log.w(TAG, "Couldn't toListBytes certificates in keystore", e);
            return null;
        }
    }

    public static Certificate[] getCertificateChain(KeyEntryResponse response) {
        if (response == null || response.metadata.certificate == null) return null;
        var leaf = toCertificate(response.metadata.certificate);
        Certificate[] chain;
        if (response.metadata.certificateChain != null) {
            var certs = toCertificates(response.metadata.certificateChain);
            chain = new Certificate[certs.size() + 1];
            final Iterator<X509Certificate> it = certs.iterator();
            int i = 1;
            while (it.hasNext()) {
                chain[i++] = it.next();
            }
        } else {
            chain = new Certificate[1];
        }
        chain[0] = leaf;
        return chain;
    }

    public static void putCertificateChain(KeyEntryResponse response, Certificate[] chain) throws Throwable {
        putCertificateChain(response.metadata, chain);
    }

    public static void putCertificateChain(KeyMetadata metadata, Certificate[] chain) throws Throwable {
        if (chain == null || chain.length == 0) return;
        metadata.certificate = chain[0].getEncoded();
        var output = new ByteArrayOutputStream();
        for (int i = 1; i < chain.length; i++) {
            output.write(chain[i].getEncoded());
        }
        metadata.certificateChain = output.toByteArray();
    }
}
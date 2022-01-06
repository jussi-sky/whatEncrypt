package com.jussi.whatencry;

import android.os.Build;
import android.util.Log;
import java.util.Base64;
import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

public class HookMain implements IXposedHookLoadPackage {

    //被HOOK的程序的包名和类名
    String packName = "com.jussi.whatecrypt";

    String TAG = "whatEncrypt";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadPackageParam) throws Throwable {

        if(loadPackageParam == null) return;
//        if(!packName.equals(loadPackageParam.packageName)) return;

        XposedBridge.log("Loaded app: " + loadPackageParam.packageName);

        /**
         * Hook Hash
         */
        XposedHelpers.findAndHookMethod("java.security.MessageDigest", // 类名
                loadPackageParam.classLoader, // 类加载器
                "getInstance", // 方法名
                String.class,   // 参数1
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "mode: " + (String) param.args[0]);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                    }
                });

        XposedHelpers.findAndHookMethod("java.security.MessageDigest",
                loadPackageParam.classLoader,
                "update",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "plain: " + byte2String((byte[]) param.args[0]));
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                    }
                });

        XposedHelpers.findAndHookMethod("java.security.MessageDigest",
                loadPackageParam.classLoader,
                "digest",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        super.beforeHookedMethod(param);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] bytes = (byte[]) param.getResult();
                        Log.d(TAG, "hash: " + byte2Hex(bytes));
                        Log.d(TAG, "===========================================");
                        Log.d(TAG, " ");
                    }
                });

        /**
         * Hook DES/AES/RSA
         */
        // getInstance
        XposedHelpers.findAndHookMethod("javax.crypto.Cipher",
                loadPackageParam.classLoader,
                "getInstance",
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG,"mode: " + (String) param.args[0]);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                    }
                });

        // DES key
//        XposedHelpers.findAndHookMethod("javax.crypto.spec.DESKeySpec",
//                loadPackageParam.classLoader,
//                "getKey",
//                new XC_MethodHook() {
//                    @Override
//                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
//                        super.beforeHookedMethod(param);
//                    }
//
//                    @Override
//                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
//                        byte[] bytes = (byte[]) param.getResult();
//                        Log.d(TAG, "DES key: " + byte2String(bytes));
//                    }
//                });

        // AES key
        XposedHelpers.findAndHookConstructor("javax.crypto.spec.SecretKeySpec",
                loadPackageParam.classLoader,
                byte[].class,
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "key: " + byte2String((byte[]) param.args[0]));
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                    }
                });

        // AES key
        XposedHelpers.findAndHookConstructor("javax.crypto.spec.SecretKeySpec",
                loadPackageParam.classLoader,
                byte[].class,
                int.class,
                int.class,
                String.class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "AES key: " + byte2String((byte[]) param.args[0]));
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        super.afterHookedMethod(param);
                    }
                });

        // RSA Public Key
        XposedHelpers.findAndHookMethod("java.security.spec.X509EncodedKeySpec",
                loadPackageParam.classLoader,
                "getEncoded",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        super.beforeHookedMethod(param);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] bytes = (byte[]) param.getResult();
                        Log.d(TAG, "RSA public key: " + byte2Base64(bytes));
                    }
                });

        // iv
        XposedHelpers.findAndHookMethod("javax.crypto.spec.IvParameterSpec",
                loadPackageParam.classLoader,
                "getIV",
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        super.beforeHookedMethod(param);
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        byte[] bytes = (byte[]) param.getResult();
                        Log.d(TAG, "iv: " + byte2String(bytes));
                    }
                });

        // doFinal
        XposedHelpers.findAndHookMethod("javax.crypto.Cipher",
                loadPackageParam.classLoader,
                "doFinal",
                byte[].class,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "plain: " + byte2String((byte[]) param.args[0]).trim());
                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Log.d(TAG, "encrypted: " + byte2Base64((byte[]) param.getResult()));
                        Log.d(TAG, "===========================================");
                        Log.d(TAG, " ");
                    }
                });

    }

    public static String byte2String(byte[] bytes) {
        return new String((byte[]) bytes);
    }

    private static final String HEX = "0123456789abcdef";

    public static String byte2Hex(byte[] byteArray) {
        if (byteArray == null || byteArray.length == 0)
            return null;

        StringBuilder sb = new StringBuilder(byteArray.length * 2);

        for (byte b : byteArray) {
            sb.append(HEX.charAt((b >> 4) & 0x0f));
            sb.append(HEX.charAt(b & 0x0f));
        }

        return sb.toString();
    }

    public static String byte2Base64(byte[] bytes){
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            return new String(Base64.getEncoder().encode(bytes));
        }
        return "";
    }
}

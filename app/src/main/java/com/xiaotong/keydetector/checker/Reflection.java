package com.xiaotong.keydetector.checker;

import android.os.IBinder;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Reflection {
    public static final int DOMAIN_APP = 2;
    public static final long NSPACE_SELF = -1;

    public static Object getIKeystoreService() throws Exception {
        Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
        Method getServiceMethod = serviceManagerClass.getMethod("getService", String.class);
        IBinder binder = (IBinder) getServiceMethod.invoke(null, "android.system.keystore2.IKeystoreService/default");

        if (binder == null) {
            throw new Exception("Could not get IKeystoreService binder");
        }

        Class<?> stubClass = Class.forName("android.system.keystore2.IKeystoreService$Stub");
        Method asInterfaceMethod = stubClass.getMethod("asInterface", IBinder.class);
        return asInterfaceMethod.invoke(null, binder);
    }

    public static Object createKeyDescriptor(String alias) throws Exception {
        Class<?> keyDescriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
        Object keyDescriptor = keyDescriptorClass.newInstance();

        Field domainField = keyDescriptorClass.getField("domain");
        domainField.setInt(keyDescriptor, DOMAIN_APP); // Domain.APP = 2

        Field nspaceField = keyDescriptorClass.getField("nspace");
        nspaceField.setLong(keyDescriptor, NSPACE_SELF); // -1

        Field aliasField = keyDescriptorClass.getField("alias");
        aliasField.set(keyDescriptor, alias);

        Field blobField = keyDescriptorClass.getField("blob");
        blobField.set(keyDescriptor, null);

        return keyDescriptor;
    }
}

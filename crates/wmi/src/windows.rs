// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

struct ComInitGuard;

impl ComInitGuard {

    fn new() -> std::io::Result<ComInitGuard> {
        // SAFETY: Simple FFI call as described in the documentation [1]. We
        // verify the return code below.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-coinitializeex
        let status = unsafe {
            windows_sys::Win32::System::Com::CoInitializeEx(
                std::ptr::null(),
                windows_sys::Win32::System::Com::COINIT_MULTITHREADED as u32,
            )
        };

        // As described in the documentation, we return the guard even if the
        // call returned `S_FALSE` or `RPC_E_CHANGED_MODE` (it means that the
        // library was initialized before) as _every_ initialization call should
        // be balanced be corresponding uninitialization.
        match status {
            windows_sys::Win32::Foundation::S_OK => {}
            windows_sys::Win32::Foundation::S_FALSE => {}
            windows_sys::Win32::Foundation::RPC_E_CHANGED_MODE => (),
            _ => return Err(std::io::Error::from_raw_os_error(status)),
        }

        Ok(ComInitGuard)
    }
}

impl Drop for ComInitGuard {

    fn drop(&mut self) {
        // SAFETY: Simple FFI call as described in the documentation [1]. If we
        // reach this line, it means that the initialization did not error and
        // should be balanced by uninitialization.
        //
        // [1]: https://learn.microsoft.com/en-us/windows/desktop/api/combaseapi/nf-combaseapi-couninitialize
        unsafe {
            windows_sys::Win32::System::Com::CoUninitialize();
        }
    }
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemLocatorVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    QueryInterface: unsafe extern "system" fn(
        this: *mut IWbemLocator,
        // TODO(@panhania): This should be of type `REFIID` but this is not
        // exposed by `windows-sys`. For the time being we use the `GUID` alias
        // as this is what the `windows-core` crate uses for it [1].
        //
        // [1]: https://github.com/microsoft/windows-rs/blob/db06b51c2ebb743efb544d40e3064efa49f28d38/crates/libs/core/src/unknown.rs#L18
        riid: windows_sys::core::GUID,
        ppvObject: *mut *mut std::ffi::c_void,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref
    AddRef: unsafe extern "system" fn(
        this: *mut IWbemLocator,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    Release: unsafe extern "system" fn(
        this: *mut IWbemLocator,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
    ConnectServer: unsafe extern "system" fn(
        this: *mut IWbemLocator,
        strNetworkResource: windows_sys::core::BSTR,
        strUser: windows_sys::core::BSTR,
        strPassword: windows_sys::core::BSTR,
        strLocale: windows_sys::core::BSTR,
        lSecurityFlags: std::ffi::c_long,
        strAuthority: windows_sys::core::BSTR,
        pCtx: *mut IWbemContext,
        ppNamespace: *mut *mut IWbemServices,
    ) -> windows_sys::core::HRESULT,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemLocator {
    lpVtbl: *const IWbemLocatorVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemcontext
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemContextVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    QueryInterface: unsafe extern "system" fn(
        this: *mut IWbemContext,
        // TODO(@panhania): This should be of type `REFIID` but this is not
        // exposed by `windows-sys`. For the time being we use the `GUID` alias
        // as this is what the `windows-core` crate uses for it [1].
        //
        // [1]: https://github.com/microsoft/windows-rs/blob/db06b51c2ebb743efb544d40e3064efa49f28d38/crates/libs/core/src/unknown.rs#L18
        riid: windows_sys::core::GUID,
        ppvObject: *mut *mut std::ffi::c_void,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref
    AddRef: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    Release: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-clone
    Clone: unsafe extern "system" fn(
        this: *mut IWbemContext,
        ppNewCopy: *mut *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-getnames
    GetNames: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
        pNames: *mut *mut windows_sys::Win32::System::Com::SAFEARRAY,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-beginenumeration
    BeginEnumeration: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-next
    Next: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
        pstrName: windows_sys::core::BSTR,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-endenumeration
    EndEnumeration: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-setvalue
    SetValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-getvalue
    GetValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-deletevalue
    DeleteValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-deleteall
    DeleteAll: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemcontext
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemContext {
    lpVtbl: *const IWbemContextVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemServicesVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    QueryInterface: unsafe extern "system" fn(
        this: *mut IWbemServices,
        // TODO(@panhania): This should be of type `REFIID` but this is not
        // exposed by `windows-sys`. For the time being we use the `GUID` alias
        // as this is what the `windows-core` crate uses for it [1].
        //
        // [1]: https://github.com/microsoft/windows-rs/blob/db06b51c2ebb743efb544d40e3064efa49f28d38/crates/libs/core/src/unknown.rs#L18
        riid: windows_sys::core::GUID,
        ppvObject: *mut *mut std::ffi::c_void,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref
    AddRef: unsafe extern "system" fn(
        this: *mut IWbemServices,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    Release: unsafe extern "system" fn(
        this: *mut IWbemServices,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-opennamespace
    OpenNamespace: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-cancelasynccall
    CancelAsyncCall: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-queryobjectsink
    QueryObjectSink: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-getobject
    GetObject: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-getobjectasync
    GetObjectAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putclass
    PutClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putclassasync
    PutClassAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteclass
    DeleteClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteclassasync
    DeleteClassAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createclassenum
    CreateClassEnum: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createclassenumasync
    CreateClassEnumAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putinstance
    PutInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putinstanceasync
    PutInstanceAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteinstance
    DeleteInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteinstanceasync
    DeleteInstanceAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createinstanceenum
    CreateInstanceEnum: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createinstanceenumasync
    CreateInstanceEnumAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
    ExecQuery: unsafe extern "system" fn(
        this: *mut IWbemServices,
        strQueryLanguage: windows_sys::core::BSTR,
        strQuery: windows_sys::core::BSTR,
        lFlags: std::ffi::c_long,
        pCtx: *mut IWbemContext,
        ppEnum: *mut *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execqueryasync
    ExecQueryAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execnotificationquery
    ExecNotificationQuery: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execnotificationqueryasync
    ExecNotificationQueryAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethod
    ExecMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethodasync
    ExecMethodAsync: *const std::ffi::c_void, // Not complete, unused.
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemServices {
    lpVtbl: *const IWbemServicesVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IEnumWbemClassObjectVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    QueryInterface: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        // TODO(@panhania): This should be of type `REFIID` but this is not
        // exposed by `windows-sys`. For the time being we use the `GUID` alias
        // as this is what the `windows-core` crate uses for it [1].
        //
        // [1]: https://github.com/microsoft/windows-rs/blob/db06b51c2ebb743efb544d40e3064efa49f28d38/crates/libs/core/src/unknown.rs#L18
        riid: windows_sys::core::GUID,
        ppvObject: *mut *mut std::ffi::c_void,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref
    AddRef: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    Release: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-reset
    Reset: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
    Next: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        lTimeout: std::ffi::c_long,
        uCount: std::ffi::c_ulong,
        apObjects: *mut *mut IWbemClassObject,
        puReturned: *mut std::ffi::c_ulong,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-nextasync
    NextAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-clone
    Clone: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        ppEnum: *mut *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-skip
    Skip: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        lTimeout: std::ffi::c_long,
        nCount: std::ffi::c_ulong,
    ) -> windows_sys::core::HRESULT,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IEnumWbemClassObject {
    lpVtbl: *const IEnumWbemClassObjectVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemClassObjectVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    QueryInterface: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
        // TODO(@panhania): This should be of type `REFIID` but this is not
        // exposed by `windows-sys`. For the time being we use the `GUID` alias
        // as this is what the `windows-core` crate uses for it [1].
        //
        // [1]: https://github.com/microsoft/windows-rs/blob/db06b51c2ebb743efb544d40e3064efa49f28d38/crates/libs/core/src/unknown.rs#L18
        riid: windows_sys::core::GUID,
        ppvObject: *mut *mut std::ffi::c_void,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-addref
    AddRef: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    Release: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getqualifierset
    GetQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get
    Get: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
        pType: *mut CIMTYPE,
        plFlavor: *mut std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-put
    Put: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-delete
    Delete: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getnames
    GetNames: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-beginenumeration
    BeginEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-next
    Next: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-endenumeration
    EndEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getpropertyqualifierset
    GetPropertyQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-clone
    Clone: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getobjecttext
    GetObjectText: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-spawnderivedclass
    SpawnDerivedClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-spawninstance
    SpawnInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-compareto
    CompareTo: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getpropertyorigin
    GetPropertyOrigin: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-inheritsfrom
    InheritsFrom: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethod
    GetMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-putmethod
    PutMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-deletemethod
    DeleteMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-beginmethodenumeration
    BeginMethodEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-nextmethod
    NextMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-endmethodenumeration
    EndMethodEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethodqualifierset
    GetMethodQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethodorigin
    GetMethodOrigin: *const std::ffi::c_void, // Not complete, unused.
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
struct IWbemClassObject {
    lpVtbl: *const IWbemClassObjectVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/ne-wbemcli-cimtype_enumeration
//
// inc/wnet/wbemcli.h
type CIMTYPE = std::ffi::c_long;

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn com_init_guard() {
        assert!(ComInitGuard::new().is_ok());
    }

    #[test]
    fn com_init_guard_sequence() {
        let guard = ComInitGuard::new().unwrap();
        drop(guard);

        let guard = ComInitGuard::new().unwrap();
        drop(guard);

        let guard = ComInitGuard::new().unwrap();
        drop(guard);
    }

    #[test]
    fn com_init_guard_nested() {
        let guard_1 = ComInitGuard::new().unwrap();
        let guard_2 = ComInitGuard::new().unwrap();
        let guard_3 = ComInitGuard::new().unwrap();

        drop(guard_1);
        drop(guard_2);
        drop(guard_3);
    }
}

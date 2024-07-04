// Copyright 2024 Google LLC
//
// Use of this source code is governed by an MIT-style license that can be found
// in the LICENSE file or at https://opensource.org/licenses/MIT.

// TODO(@panhania): Definitions from this module should come from `windows-sys`
// but for some reason are not there (maybe COM support is outside of scope?).

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemlocator
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemLocatorVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    pub QueryInterface: unsafe extern "system" fn(
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
    pub AddRef: unsafe extern "system" fn(
        this: *mut IWbemLocator,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    pub Release: unsafe extern "system" fn(
        this: *mut IWbemLocator,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemlocator-connectserver
    pub ConnectServer: unsafe extern "system" fn(
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
pub struct IWbemLocator {
    pub lpVtbl: *const IWbemLocatorVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemcontext
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemContextVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    pub QueryInterface: unsafe extern "system" fn(
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
    pub AddRef: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    pub Release: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-clone
    pub Clone: unsafe extern "system" fn(
        this: *mut IWbemContext,
        ppNewCopy: *mut *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-getnames
    pub GetNames: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
        pNames: *mut *mut windows_sys::Win32::System::Com::SAFEARRAY,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-beginenumeration
    pub BeginEnumeration: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-next
    pub Next: unsafe extern "system" fn(
        this: *mut IWbemContext,
        lFlags: std::ffi::c_long,
        pstrName: windows_sys::core::BSTR,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-endenumeration
    pub EndEnumeration: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-setvalue
    pub SetValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-getvalue
    pub GetValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-deletevalue
    pub DeleteValue: unsafe extern "system" fn(
        this: *mut IWbemContext,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemcontext-deleteall
    pub DeleteAll: unsafe extern "system" fn(
        this: *mut IWbemContext,
    ) -> windows_sys::core::HRESULT,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemcontext
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemContext {
    pub lpVtbl: *const IWbemContextVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemServicesVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    pub QueryInterface: unsafe extern "system" fn(
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
    pub AddRef: unsafe extern "system" fn(
        this: *mut IWbemServices,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    pub Release: unsafe extern "system" fn(
        this: *mut IWbemServices,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-opennamespace
    pub OpenNamespace: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-cancelasynccall
    pub CancelAsyncCall: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-queryobjectsink
    pub QueryObjectSink: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-getobject
    pub GetObject: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-getobjectasync
    pub GetObjectAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putclass
    pub PutClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putclassasync
    pub PutClassAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteclass
    pub DeleteClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteclassasync
    pub DeleteClassAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createclassenum
    pub CreateClassEnum: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createclassenumasync
    pub CreateClassEnumAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putinstance
    pub PutInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-putinstanceasync
    pub PutInstanceAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteinstance
    pub DeleteInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-deleteinstanceasync
    pub DeleteInstanceAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createinstanceenum
    pub CreateInstanceEnum: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-createinstanceenumasync
    pub CreateInstanceEnumAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execquery
    pub ExecQuery: unsafe extern "system" fn(
        this: *mut IWbemServices,
        strQueryLanguage: windows_sys::core::BSTR,
        strQuery: windows_sys::core::BSTR,
        lFlags: std::ffi::c_long,
        pCtx: *mut IWbemContext,
        ppEnum: *mut *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execqueryasync
    pub ExecQueryAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execnotificationquery
    pub ExecNotificationQuery: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execnotificationqueryasync
    pub ExecNotificationQueryAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethod
    pub ExecMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemservices-execmethodasync
    pub ExecMethodAsync: *const std::ffi::c_void, // Not complete, unused.
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemservices
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemServices {
    pub lpVtbl: *const IWbemServicesVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-ienumwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IEnumWbemClassObjectVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    pub QueryInterface: unsafe extern "system" fn(
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
    pub AddRef: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    pub Release: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-reset
    pub Reset: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-next
    pub Next: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        lTimeout: std::ffi::c_long,
        uCount: std::ffi::c_ulong,
        apObjects: *mut *mut IWbemClassObject,
        puReturned: *mut std::ffi::c_ulong,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-nextasync
    pub NextAsync: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-clone
    pub Clone: unsafe extern "system" fn(
        this: *mut IEnumWbemClassObject,
        ppEnum: *mut *mut IEnumWbemClassObject,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-ienumwbemclassobject-skip
    pub Skip: unsafe extern "system" fn(
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
pub struct IEnumWbemClassObject {
    pub lpVtbl: *const IEnumWbemClassObjectVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemClassObjectVtbl {
    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-queryinterface(refiid_void)
    pub QueryInterface: unsafe extern "system" fn(
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
    pub AddRef: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/unknwn/nf-unknwn-iunknown-release
    pub Release: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
    ) -> std::ffi::c_ulong,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getqualifierset
    pub GetQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-get
    pub Get: unsafe extern "system" fn(
        this: *mut IWbemClassObject,
        wszName: windows_sys::core::PCWSTR,
        lFlags: std::ffi::c_long,
        pValue: *mut windows_sys::Win32::System::Variant::VARIANT,
        pType: *mut CIMTYPE,
        plFlavor: *mut std::ffi::c_long,
    ) -> windows_sys::core::HRESULT,

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-put
    pub Put: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-delete
    pub Delete: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getnames
    pub GetNames: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-beginenumeration
    pub BeginEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-next
    pub Next: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-endenumeration
    pub EndEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getpropertyqualifierset
    pub GetPropertyQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-clone
    pub Clone: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getobjecttext
    pub GetObjectText: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-spawnderivedclass
    pub SpawnDerivedClass: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-spawninstance
    pub SpawnInstance: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-compareto
    pub CompareTo: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getpropertyorigin
    pub GetPropertyOrigin: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-inheritsfrom
    pub InheritsFrom: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethod
    pub GetMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-putmethod
    pub PutMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-deletemethod
    pub DeleteMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-beginmethodenumeration
    pub BeginMethodEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-nextmethod
    pub NextMethod: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-endmethodenumeration
    pub EndMethodEnumeration: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethodqualifierset
    pub GetMethodQualifierSet: *const std::ffi::c_void, // Not complete, unused.

    // https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nf-wbemcli-iwbemclassobject-getmethodorigin
    pub GetMethodOrigin: *const std::ffi::c_void, // Not complete, unused.
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/nn-wbemcli-iwbemclassobject
//
// inc/wnet/wbemcli.h
#[allow(non_snake_case)]
#[repr(C)]
pub struct IWbemClassObject {
    pub lpVtbl: *const IWbemClassObjectVtbl,
}

// https://learn.microsoft.com/en-us/windows/win32/api/wbemcli/ne-wbemcli-cimtype_enumeration
//
// inc/wnet/wbemcli.h
pub type CIMTYPE = std::ffi::c_long;

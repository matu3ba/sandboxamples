const win = @import("../win.zig");

pub extern "advapi32" fn GetSecurityInfo(
    handle: ?win.HANDLE,
    ObjectType: win.SE_OBJECT_TYPE,
    SecurityInfo: win.DWORD,
    ppsidOwner: ?*win.PSID,
    ppsidGroup: ?*win.PSID,
    ppDacl: ?*?*win.ACL,
    ppSacl: ?*?*win.ACL,
    ppSecurityDescriptor: ?*win.PSECURITY_DESCRIPTOR
) win.DWORD;
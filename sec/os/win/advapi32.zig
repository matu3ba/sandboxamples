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
) callconv(win.WINAPI) win.DWORD;

// error == 0
pub extern "advapi32" fn LookupAccountSidW(
    lpSystemName: ?[*:0]const u16,
    Sid: win.PSID,
    Name: ?[*:0]u16,
    cchName: ?*u32,
    ReferencedDomainName: ?[*:0]u16,
    cchReferencedDomainName: ?*u32,
    peUse: ?*win.SID_NAME_USE,
) callconv(win.WINAPI) win.BOOL;
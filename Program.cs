using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace ACEHound
{
    internal class Program
    {
        // =========================================================
        // ACEHOUND PROJECT PROGRESS
        // =========================================================

        // Module 1  CLI Framework             ✅
        // Module 2  AD Discovery              ✅
        // Module 3  LDAP User Enumeration     ✅
        // Module 4  ACL Enumeration           ✅
        // Module 5  ACE Parsing               ✅
        // Module 6  Permission Analysis       ✅
        // Module 7  Interesting ACLs          ✅
        // Module 8  ACL Search                ✅
        // Module 9  Relationship Mapping          ✅
        // Module 10 Console Graph             ✅
        // Module 11 Path Analysis              ⬜
        // Module 12 Abuse Guidance            ✅
        // Module 13 Reporting                 ✅
        // Module 14 Testing                   ✅
        // Module 15 Documentation             ✅


        // =========================================================
        // SPECIAL ACTIVE DIRECTORY GUIDs
        // =========================================================

        // ForceChangePassword / Reset Password
        static readonly Guid ResetPasswordGuid =
            new Guid("00299570-246d-11d0-a768-00aa006e0529");

        // DCSync
        static readonly Guid GetChangesGuid =
            new Guid("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");

        static readonly Guid GetChangesAllGuid =
            new Guid("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

        static readonly Guid GetChangesInFilteredSetGuid =
            new Guid("89e95b76-444d-4c62-991a-0facbeda640c");


        // =========================================================
        // IMPORTANT ATTRIBUTE GUIDs
        // =========================================================

        // member attribute
        static readonly Guid MemberAttributeGuid =
            new Guid("bf9679c0-0de6-11d0-a285-00aa003049e2");

        // servicePrincipalName
        static readonly Guid ServicePrincipalNameGuid =
            new Guid("bf967a0a-0de6-11d0-a285-00aa003049e2");

        // userAccountControl
        static readonly Guid UserAccountControlGuid =
            new Guid("bf967a68-0de6-11d0-a285-00aa003049e2");

        // msDS-AllowedToActOnBehalfOfOtherIdentity
        static readonly Guid AllowedToActGuid =
            new Guid("3f78c3e5-f79a-46bd-a0b8-9d18116ddc79");


        // =========================================================
        // gMSA
        // =========================================================

        static readonly string GmsaObjectClass =
            "msDS-GroupManagedServiceAccount";


        // =========================================================
        // GRAPH
        // =========================================================

        class GraphEdge
        {
            public string Principal;
            public string Permission;
            public string Target;
        }

        static List<GraphEdge> graphEdges =
            new List<GraphEdge>();


        // =========================================================
        // HELP
        // =========================================================

        static void ShowHelp()
        {
            Console.WriteLine();
            Console.WriteLine("==========================================");
            Console.WriteLine("                 ACEHound");
            Console.WriteLine("==========================================");
            Console.WriteLine();

            Console.WriteLine(
                "Active Directory ACL Analysis Tool");

            Console.WriteLine();

            Console.WriteLine("Usage:");
            Console.WriteLine();

            Console.WriteLine(
                "  ACEHound --help");

            Console.WriteLine(
                "  ACEHound --version");

            Console.WriteLine(
                "  ACEHound interesting");

            Console.WriteLine(
                "  ACEHound user <username>");

            Console.WriteLine(
                "  ACEHound permission <permission>");

            Console.WriteLine();

            Console.WriteLine("Examples:");
            Console.WriteLine();

            Console.WriteLine(
                "  ACEHound user administrator");

            Console.WriteLine(
                "  ACEHound interesting");

            Console.WriteLine(
                "  ACEHound permission GenericAll");

            Console.WriteLine(
                "  ACEHound permission GenericWrite");

            Console.WriteLine(
                "  ACEHound permission ForceChangePassword");

            Console.WriteLine(
                "  ACEHound permission AddMember");

            Console.WriteLine(
                "  ACEHound permission ReadGMSAPassword");

            Console.WriteLine();
        }


        // =========================================================
        // VERSION
        // =========================================================

        static void ShowVersion()
        {
            Console.WriteLine(
                "ACEHound v0.1 by Yamish Marshall");
        }


        // =========================================================
        // ROOT DSE
        // =========================================================

        static DirectoryEntry GetRootDSE()
        {
            DirectoryEntry root =
                new DirectoryEntry("LDAP://RootDSE");

            root.RefreshCache();

            return root;
        }


        // =========================================================
        // USER SEARCH
        // =========================================================

        static void SearchUser(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(
                    "[-] Username required.");

                Console.WriteLine(
                    "[*] Usage: ACEHound user <username>");

                return;
            }

            string username = args[1];

            Console.WriteLine();
            Console.WriteLine(
                $"[*] Searching ACLs for user: {username}");

            Console.WriteLine();

            try
            {
                using (DirectoryEntry root = GetRootDSE())
                {
                    string baseDn =
                        root.Properties[
                            "defaultNamingContext"]
                            .Value.ToString();

                    graphEdges.Clear();

                    SearchUserACLs(
                        baseDn,
                        username);

                    ShowConsoleGraph();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] Error: {ex.Message}");
            }
        }


        // =========================================================
        // SEARCH USER ACLs
        // =========================================================

        static void SearchUserACLs(
            string baseDn,
            string username)
        {
            using (DirectoryEntry domain =
                new DirectoryEntry(
                    $"LDAP://{baseDn}"))
            {
                string filter =
                    $"(&(objectCategory=person)" +
                    $"(sAMAccountName=" +
                    $"{EscapeLDAP(username)}))";

                using (DirectorySearcher searcher =
                    new DirectorySearcher(domain))
                {
                    searcher.Filter = filter;

                    searcher.PropertiesToLoad.Add(
                        "distinguishedName");

                    searcher.PropertiesToLoad.Add(
                        "objectSid");

                    SearchResult result =
                        searcher.FindOne();

                    if (result == null)
                    {
                        Console.WriteLine(
                            $"[-] User not found: {username}");

                        return;
                    }

                    string userDn =
                        GetProperty(
                            result,
                            "distinguishedName");

                    SecurityIdentifier userSid =
                        GetUserSid(result);

                    if (string.IsNullOrEmpty(userDn) ||
                        userSid == null)
                    {
                        Console.WriteLine(
                            "[-] Could not retrieve the user's DN or SID.");

                        return;
                    }

                    Console.WriteLine(
                        $"[+] User found: {userDn}");

                    Console.WriteLine(
                        $"[+] SID        : {userSid.Value}");

                    Console.WriteLine();

                    // -----------------------------------------------------
                    // INBOUND RELATIONSHIPS
                    // Principal -> Permission -> Selected User
                    // -----------------------------------------------------
                    EnumerateInboundPermissions(userDn);

                    // -----------------------------------------------------
                    // OUTBOUND RELATIONSHIPS
                    // Selected User -> Permission -> Target
                    // -----------------------------------------------------
                    EnumerateOutboundPermissions(
                        baseDn,
                        userSid);
                }
            }
        }


        // =========================================================
        // GET USER SID
        // =========================================================

        static SecurityIdentifier GetUserSid(
            SearchResult result)
        {
            try
            {
                if (!result.Properties.Contains("objectSid"))
                    return null;

                if (result.Properties["objectSid"].Count == 0)
                    return null;

                byte[] sidBytes =
                    result.Properties["objectSid"][0] as byte[];

                if (sidBytes == null || sidBytes.Length == 0)
                    return null;

                return new SecurityIdentifier(
                    sidBytes,
                    0);
            }
            catch
            {
                return null;
            }
        }


        // =========================================================
        // INBOUND PERMISSIONS
        // Principal -> Permission -> User
        // =========================================================

        static void EnumerateInboundPermissions(
            string userDn)
        {
            Console.WriteLine(
                "==========================================");

            Console.WriteLine(
                "          INBOUND ACL RELATIONSHIPS");

            Console.WriteLine(
                "==========================================");

            Console.WriteLine();

            try
            {
                ActiveDirectorySecurity security =
                    GetSecurityDescriptor(userDn);

                AuthorizationRuleCollection rules =
                    security.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                int count = 0;

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    if (rule.AccessControlType !=
                        AccessControlType.Allow)
                    {
                        continue;
                    }

                    string permission =
                        GetGraphPermission(rule);

                    if (string.IsNullOrEmpty(permission))
                    {
                        continue;
                    }

                    count++;

                    string principal =
                        ResolveIdentityReference(rule.IdentityReference);

                    Console.WriteLine(
                        $"---------- INBOUND ACL {count} ----------");

                    Console.WriteLine(
                        $"Principal  : {principal}");

                    Console.WriteLine(
                        $"Permission : {permission}");

                    Console.WriteLine(
                        $"Target     : {userDn}");

                    Console.WriteLine();

                    ParseACE(rule);
                    AnalyzePermission(rule);

                    string guidancePermission =
                        GetGuidancePermission(rule);

                    if (!string.IsNullOrEmpty(guidancePermission))
                    {
                        PrintFinding(
                            "INFO",
                            guidancePermission,
                            "Relevant ACL relationship discovered for the selected user.");

                        ShowAbuseGuidance(
                            guidancePermission,
                            userDn,
                            principal);
                    }

                    graphEdges.Add(
                        new GraphEdge
                        {
                            Principal = principal,
                            Permission = permission,
                            Target = userDn
                        });

                    Console.WriteLine();
                }

                Console.WriteLine(
                    $"[+] Inbound relationships: {count}");

                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] Inbound ACL enumeration failed: {ex.Message}");

                Console.WriteLine();
            }
        }


        // =========================================================
        // OUTBOUND PERMISSIONS
        // User -> Permission -> Target
        // =========================================================

        static void EnumerateOutboundPermissions(
            string baseDn,
            SecurityIdentifier userSid)
        {
            Console.WriteLine(
                "==========================================");

            Console.WriteLine(
                "          OUTBOUND ACL RELATIONSHIPS");

            Console.WriteLine(
                "==========================================");

            Console.WriteLine();

            try
            {
                using (DirectoryEntry domain =
                    new DirectoryEntry(
                        $"LDAP://{baseDn}"))
                {
                    using (DirectorySearcher searcher =
                        new DirectorySearcher(domain))
                    {
                        searcher.Filter =
                            "(objectClass=*)";

                        searcher.PropertiesToLoad.Add(
                            "distinguishedName");

                        searcher.PageSize = 500;

                        SearchResultCollection results =
                            searcher.FindAll();

                        int count = 0;

                        foreach (SearchResult result in results)
                        {
                            string target =
                                GetProperty(
                                    result,
                                    "distinguishedName");

                            if (string.IsNullOrEmpty(target))
                                continue;

                            try
                            {
                                ActiveDirectorySecurity security =
                                    GetSecurityDescriptor(target);

                                AuthorizationRuleCollection rules =
                                    security.GetAccessRules(
                                        true,
                                        true,
                                        typeof(SecurityIdentifier));

                                foreach (ActiveDirectoryAccessRule rule in rules)
                                {
                                    if (rule.AccessControlType !=
                                        AccessControlType.Allow)
                                    {
                                        continue;
                                    }

                                    SecurityIdentifier principalSid =
                                        rule.IdentityReference
                                            as SecurityIdentifier;

                                    if (principalSid == null ||
                                        !principalSid.Equals(userSid))
                                    {
                                        continue;
                                    }

                                    string permission =
                                        GetGraphPermission(rule);

                                    if (string.IsNullOrEmpty(permission))
                                    {
                                        continue;
                                    }

                                    count++;

                                    string principal =
                                        ResolveIdentityReference(rule.IdentityReference);

                                    Console.WriteLine(
                                        $"---------- OUTBOUND ACL {count} ----------");

                                    Console.WriteLine(
                                        $"Principal  : {principal}");

                                    Console.WriteLine(
                                        $"Permission : {permission}");

                                    Console.WriteLine(
                                        $"Target     : {target}");

                                    Console.WriteLine();

                                    ParseACE(rule);
                                    AnalyzePermission(rule);

                                    string guidancePermission =
                                        GetGuidancePermission(rule);

                                    if (!string.IsNullOrEmpty(guidancePermission))
                                    {
                                        PrintFinding(
                                            "INFO",
                                            guidancePermission,
                                            "Relevant ACL relationship granted to the selected user.");

                                        ShowAbuseGuidance(
                                            guidancePermission,
                                            target,
                                            principal);
                                    }

                                    graphEdges.Add(
                                        new GraphEdge
                                        {
                                            Principal = principal,
                                            Permission = permission,
                                            Target = target
                                        });

                                    Console.WriteLine();
                                }
                            }
                            catch
                            {
                                // Ignore individual objects that cannot be read.
                            }
                        }

                        Console.WriteLine(
                            $"[+] Outbound relationships: {count}");

                        Console.WriteLine();
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] Outbound ACL enumeration failed: {ex.Message}");

                Console.WriteLine();
            }
        }


        // =========================================================
        // SECURITY DESCRIPTOR
        // =========================================================

        static ActiveDirectorySecurity GetSecurityDescriptor(
            string distinguishedName)
        {
            using (DirectoryEntry entry =
                new DirectoryEntry(
                    $"LDAP://{distinguishedName}"))
            {
                entry.Options.SecurityMasks =
                    SecurityMasks.Dacl;

                return entry.ObjectSecurity;
            }
        }


        // =========================================================
        // gMSA SECURITY DESCRIPTOR
        // =========================================================

        static ActiveDirectorySecurity
            GetGmsaMembershipSecurityDescriptor(
                string distinguishedName)
        {
            using (DirectoryEntry entry =
                new DirectoryEntry(
                    $"LDAP://{distinguishedName}"))
            {
                entry.RefreshCache(
                    new string[]
                    {
                        "msDS-GroupMSAMembership"
                    });

                if (!entry.Properties.Contains(
                    "msDS-GroupMSAMembership"))
                {
                    return null;
                }

                if (entry.Properties[
                    "msDS-GroupMSAMembership"].Count == 0)
                {
                    return null;
                }

                byte[] descriptorBytes =
                    entry.Properties[
                        "msDS-GroupMSAMembership"][0]
                    as byte[];

                if (descriptorBytes == null ||
                    descriptorBytes.Length == 0)
                {
                    return null;
                }

                ActiveDirectorySecurity security =
                    new ActiveDirectorySecurity();

                security.SetSecurityDescriptorBinaryForm(
                    descriptorBytes);

                return security;
            }
        }


        // =========================================================
        // IS gMSA
        // =========================================================

        static bool IsGMSA(
            string distinguishedName)
        {
            try
            {
                using (DirectoryEntry entry =
                    new DirectoryEntry(
                        $"LDAP://{distinguishedName}"))
                {
                    entry.RefreshCache(
                        new string[]
                        {
                            "objectClass"
                        });

                    if (!entry.Properties.Contains(
                        "objectClass"))
                    {
                        return false;
                    }

                    foreach (
                        object objectClass
                        in entry.Properties["objectClass"])
                    {
                        if (objectClass == null)
                            continue;

                        if (objectClass.ToString().Equals(
                            GmsaObjectClass,
                            StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
        }


        // =========================================================
        // GET gMSA RULES
        // =========================================================

        static AuthorizationRuleCollection
            GetGmsaMembershipRules(
                string distinguishedName)
        {
            ActiveDirectorySecurity security =
                GetGmsaMembershipSecurityDescriptor(
                    distinguishedName);

            if (security == null)
                return null;

            return security.GetAccessRules(
                true,
                true,
                typeof(SecurityIdentifier));
        }


        // =========================================================
        // gMSA PASSWORD DETECTION
        // =========================================================

        static void DetectReadGMSAPassword(
            string distinguishedName)
        {
            try
            {
                if (!IsGMSA(distinguishedName))
                    return;

                AuthorizationRuleCollection rules =
                    GetGmsaMembershipRules(
                        distinguishedName);

                if (rules == null)
                    return;

                foreach (
                    ActiveDirectoryAccessRule rule
                    in rules)
                {
                    if (rule.AccessControlType !=
                        AccessControlType.Allow)
                    {
                        continue;
                    }

                    if (!GmsaPasswordReadMatches(rule))
                        continue;

                    string principal =
                        ResolveIdentityReference(rule.IdentityReference);

                    Console.WriteLine();
                    Console.WriteLine(
                        "---------- gMSA PASSWORD ACCESS ----------");

                    Console.WriteLine(
                        "[!] ReadGMSAPassword detected");

                    Console.WriteLine(
                        $"    Principal : {principal}");

                    Console.WriteLine(
                        $"    Rights    : {rule.ActiveDirectoryRights}");

                    Console.WriteLine(
                        $"    Target    : {distinguishedName}");

                    PrintFinding(
                        "HIGH",
                        "ReadGMSAPassword",
                        "Principal can access the managed " +
                        "credential of the gMSA.");

                    ShowAbuseGuidance(
                        "ReadGMSAPassword",
                        distinguishedName,
                        principal);

                    AddGmsaGraphEdge(
                        rule,
                        distinguishedName);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] gMSA detection failed: {ex.Message}");
            }
        }


        // =========================================================
        // gMSA PASSWORD MATCH
        // =========================================================

        static bool GmsaPasswordReadMatches(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            if ((rights &
                ActiveDirectoryRights.ReadProperty) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.GenericRead) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                return true;

            return false;
        }


        // =========================================================
        // ACE ENUMERATION
        // =========================================================

        static void EnumerateACE(
            string distinguishedName)
        {
            try
            {
                Console.WriteLine(
                    "==========================================");

                Console.WriteLine(
                    "                ACE PARSING");

                Console.WriteLine(
                    "==========================================");

                Console.WriteLine();

                ActiveDirectorySecurity security =
                    GetSecurityDescriptor(
                        distinguishedName);

                AuthorizationRuleCollection rules =
                    security.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                Console.WriteLine(
                    $"[+] ACEs found: {rules.Count}");

                Console.WriteLine();

                int aceNumber = 1;

                foreach (
                    ActiveDirectoryAccessRule rule
                    in rules)
                {
                    Console.WriteLine(
                        $"========== ACE {aceNumber} ==========");

                    ParseACE(rule);

                    AnalyzePermission(rule);

                    bool interesting =
                        IsInterestingRule(rule);

                    if (interesting)
                    {
                        DetectInterestingACL(
                            rule,
                            distinguishedName);
                    }

                    if (rule.AccessControlType ==
                        AccessControlType.Allow)
                    {
                        AddGraphEdge(
                            rule,
                            distinguishedName);
                    }

                    Console.WriteLine();

                    aceNumber++;
                }

                // Special gMSA ACL
                DetectReadGMSAPassword(
                    distinguishedName);
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] ACE enumeration failed: {ex.Message}");
            }
        }


        // =========================================================
        // ACE PARSING
        // =========================================================

        static void ParseACE(
            ActiveDirectoryAccessRule rule)
        {
            Console.WriteLine(
                $"Identity : {rule.IdentityReference}");

            Console.WriteLine(
                $"Type     : {rule.AccessControlType}");

            Console.WriteLine(
                $"Rights   : {rule.ActiveDirectoryRights}");

            Console.WriteLine(
                $"Inherited: {rule.IsInherited}");

            SecurityIdentifier sid =
                ExtractSID(rule);

            if (sid != null)
            {
                Console.WriteLine(
                    $"SID      : {sid.Value}");
            }

            int accessMask =
                ParseAccessMask(rule);

            Console.WriteLine(
                $"AccessMask: 0x{accessMask:X8}");

            Console.WriteLine(
                $"ObjectType: {rule.ObjectType}");
        }


        // =========================================================
        // SID EXTRACTION
        // =========================================================

        static SecurityIdentifier ExtractSID(
            ActiveDirectoryAccessRule rule)
        {
            try
            {
                return rule.IdentityReference
                    as SecurityIdentifier;
            }
            catch
            {
                return null;
            }
        }


        // =========================================================
        // ACCESS MASK
        // =========================================================

        static int ParseAccessMask(
            ActiveDirectoryAccessRule rule)
        {
            return (int)rule.ActiveDirectoryRights;
        }


        // =========================================================
        // PERMISSION ANALYSIS
        // =========================================================

        static void AnalyzePermission(
            ActiveDirectoryAccessRule rule)
        {
            Console.WriteLine();
            Console.WriteLine(
                "---------- PERMISSION ANALYSIS ----------");

            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;

            Console.WriteLine(
                $"Raw Rights : {rights}");

            Console.WriteLine();

            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                Console.WriteLine(
                    "  [+] GenericAll");

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
                Console.WriteLine(
                    "  [+] GenericWrite");

            if ((rights &
                ActiveDirectoryRights.GenericRead) != 0)
                Console.WriteLine(
                    "  [+] GenericRead");

            if ((rights &
                ActiveDirectoryRights.GenericExecute) != 0)
                Console.WriteLine(
                    "  [+] GenericExecute");

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
                Console.WriteLine(
                    "  [+] WriteDacl");

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
                Console.WriteLine(
                    "  [+] WriteOwner");

            if ((rights &
                ActiveDirectoryRights.ReadControl) != 0)
                Console.WriteLine(
                    "  [+] ReadControl");

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0)
                Console.WriteLine(
                    "  [+] WriteProperty");

            if ((rights &
                ActiveDirectoryRights.ReadProperty) != 0)
                Console.WriteLine(
                    "  [+] ReadProperty");

            if ((rights &
                ActiveDirectoryRights.Self) != 0)
                Console.WriteLine(
                    "  [+] Self");

            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
                Console.WriteLine(
                    "  [+] CreateChild");

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
                Console.WriteLine(
                    "  [+] DeleteChild");

            if ((rights &
                ActiveDirectoryRights.DeleteTree) != 0)
                Console.WriteLine(
                    "  [+] DeleteTree");

            if ((rights &
                ActiveDirectoryRights.ListChildren) != 0)
                Console.WriteLine(
                    "  [+] ListChildren");

            if ((rights &
                ActiveDirectoryRights.ListObject) != 0)
                Console.WriteLine(
                    "  [+] ListObject");

            if ((rights &
                ActiveDirectoryRights.Delete) != 0)
                Console.WriteLine(
                    "  [+] Delete");

            if ((rights &
                ActiveDirectoryRights.Synchronize) != 0)
                Console.WriteLine(
                    "  [+] Synchronize");


            // =====================================================
            // SPECIAL EXTENDED RIGHTS
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == ResetPasswordGuid)
            {
                Console.WriteLine(
                    "  [!] ForceChangePassword");
            }

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesGuid)
            {
                Console.WriteLine(
                    "  [!] DS-Replication-Get-Changes");
            }

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesAllGuid)
            {
                Console.WriteLine(
                    "  [!] DS-Replication-Get-Changes-All");
            }

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesInFilteredSetGuid)
            {
                Console.WriteLine(
                    "  [!] DS-Replication-Get-Changes-In-Filtered-Set");
            }


            // =====================================================
            // ATTRIBUTE-SPECIFIC RIGHTS
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0)
            {
                if (objectType == MemberAttributeGuid)
                {
                    Console.WriteLine(
                        "  [!] AddMember / ModifyGroupMembership");
                }

                if (objectType == ServicePrincipalNameGuid)
                {
                    Console.WriteLine(
                        "  [!] Write servicePrincipalName");
                }

                if (objectType == UserAccountControlGuid)
                {
                    Console.WriteLine(
                        "  [!] Write userAccountControl");
                }

                if (objectType == AllowedToActGuid)
                {
                    Console.WriteLine(
                        "  [!] Write msDS-AllowedToActOnBehalfOfOtherIdentity");
                }
            }

            Console.WriteLine();

            Console.WriteLine(
                $"Classification : {ClassifyPermission(rule)}");
        }


        // =========================================================
        // CLASSIFICATION
        // =========================================================

        static string ClassifyPermission(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;

            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                return "CRITICAL - GenericAll";

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
                return "CRITICAL - WriteDacl";

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
                return "CRITICAL - WriteOwner";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == ResetPasswordGuid)
                return "CRITICAL - ForceChangePassword";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesGuid)
                return "CRITICAL - DS-Replication-Get-Changes";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesAllGuid)
                return "CRITICAL - DS-Replication-Get-Changes-All";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesInFilteredSetGuid)
                return "CRITICAL - DS-Replication-Get-Changes-In-Filtered-Set";

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
                return "HIGH - GenericWrite";

            if (IsInterestingWriteProperty(rule))
                return "HIGH - Sensitive WriteProperty";

            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
                return "MEDIUM - CreateChild";

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
                return "MEDIUM - DeleteChild";

            if ((rights &
                ActiveDirectoryRights.GenericRead) != 0)
                return "LOW - GenericRead";

            if ((rights &
                ActiveDirectoryRights.ReadProperty) != 0)
                return "LOW - ReadProperty";

            if ((rights &
                ActiveDirectoryRights.ReadControl) != 0)
                return "LOW - ReadControl";

            return "INFO - Other Permission";
        }


        // =========================================================
        // INTERESTING WriteProperty DETECTION
        // =========================================================

        static bool IsInterestingWriteProperty(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            if ((rights &
                ActiveDirectoryRights.WriteProperty) == 0)
            {
                return false;
            }

            Guid objectType =
                rule.ObjectType;

            if (objectType == MemberAttributeGuid)
                return true;

            if (objectType == ServicePrincipalNameGuid)
                return true;

            if (objectType == UserAccountControlGuid)
                return true;

            if (objectType == AllowedToActGuid)
                return true;

            return false;
        }


        // =========================================================
        // INTERESTING ACL DETECTION
        // =========================================================

        static void DetectInterestingACL(
            ActiveDirectoryAccessRule rule,
            string target)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;

            string principal =
                ResolveIdentityReference(rule.IdentityReference);


            // =====================================================
            // GenericAll
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
            {
                PrintFinding(
                    "CRITICAL",
                    "GenericAll",
                    "Full control over the target object.");

                ShowAbuseGuidance(
                    "GenericAll",
                    target,
                    principal);
            }


            // =====================================================
            // WriteDacl
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
            {
                PrintFinding(
                    "CRITICAL",
                    "WriteDacl",
                    "Can modify the target object's DACL.");

                ShowAbuseGuidance(
                    "WriteDacl",
                    target,
                    principal);
            }


            // =====================================================
            // WriteOwner
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
            {
                PrintFinding(
                    "CRITICAL",
                    "WriteOwner",
                    "Can modify ownership of the target.");

                ShowAbuseGuidance(
                    "WriteOwner",
                    target,
                    principal);
            }


            // =====================================================
            // GenericWrite
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
            {
                PrintFinding(
                    "HIGH",
                    "GenericWrite",
                    "Broad write access to the target.");

                ShowAbuseGuidance(
                    "GenericWrite",
                    target,
                    principal);
            }


            // =====================================================
            // ForceChangePassword
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == ResetPasswordGuid)
            {
                PrintFinding(
                    "CRITICAL",
                    "ForceChangePassword",
                    "Has the Reset Password extended right.");

                ShowAbuseGuidance(
                    "ForceChangePassword",
                    target,
                    principal);
            }


            // =====================================================
            // DCSync - Get Changes
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesGuid)
            {
                PrintFinding(
                    "CRITICAL",
                    "DS-Replication-Get-Changes",
                    "Has a directory replication permission.");

                ShowAbuseGuidance(
                    "DS-Replication-Get-Changes",
                    target,
                    principal);
            }


            // =====================================================
            // DCSync - Get Changes All
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesAllGuid)
            {
                PrintFinding(
                    "CRITICAL",
                    "DS-Replication-Get-Changes-All",
                    "Has the replication permission for " +
                    "all replicated data.");

                ShowAbuseGuidance(
                    "DS-Replication-Get-Changes-All",
                    target,
                    principal);
            }


            // =====================================================
            // DCSync - Filtered Set
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesInFilteredSetGuid)
            {
                PrintFinding(
                    "HIGH",
                    "DS-Replication-Get-Changes-In-Filtered-Set",
                    "Has a filtered-set replication permission.");

                ShowAbuseGuidance(
                    "DS-Replication-Get-Changes-In-Filtered-Set",
                    target,
                    principal);
            }


            // =====================================================
            // AddMember
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == MemberAttributeGuid)
            {
                PrintFinding(
                    "HIGH",
                    "AddMember",
                    "Can modify the member attribute.");

                ShowAbuseGuidance(
                    "AddMember",
                    target,
                    principal);
            }


            // =====================================================
            // servicePrincipalName
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == ServicePrincipalNameGuid)
            {
                PrintFinding(
                    "HIGH",
                    "WriteSPN",
                    "Can modify servicePrincipalName.");

                ShowAbuseGuidance(
                    "WriteSPN",
                    target,
                    principal);
            }


            // =====================================================
            // userAccountControl
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == UserAccountControlGuid)
            {
                PrintFinding(
                    "HIGH",
                    "WriteUserAccountControl",
                    "Can modify userAccountControl.");

                ShowAbuseGuidance(
                    "WriteUserAccountControl",
                    target,
                    principal);
            }


            // =====================================================
            // AllowedToAct
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == AllowedToActGuid)
            {
                PrintFinding(
                    "HIGH",
                    "WriteAllowedToAct",
                    "Can modify " +
                    "msDS-AllowedToActOnBehalfOfOtherIdentity.");

                ShowAbuseGuidance(
                    "WriteAllowedToAct",
                    target,
                    principal);
            }


            // =====================================================
            // CreateChild
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
            {
                PrintFinding(
                    "MEDIUM",
                    "CreateChild",
                    "Can create child objects.");

                ShowAbuseGuidance(
                    "CreateChild",
                    target,
                    principal);
            }


            // =====================================================
            // DeleteChild
            // =====================================================

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
            {
                PrintFinding(
                    "MEDIUM",
                    "DeleteChild",
                    "Can delete child objects.");

                ShowAbuseGuidance(
                    "DeleteChild",
                    target,
                    principal);
            }
        }


        // =========================================================
        // PRINT FINDING
        // =========================================================

        static void PrintFinding(
            string severity,
            string permission,
            string reason)
        {
            Console.WriteLine();

            Console.WriteLine(
                $"[!] Severity   : {severity}");

            Console.WriteLine(
                $"[!] Permission : {permission}");

            Console.WriteLine(
                $"[!] Reason     : {reason}");
        }


        // =========================================================
        // MODULE 12
        // ABUSE GUIDANCE
        // =========================================================

        static void ShowAbuseGuidance(
    string permission,
    string target,
    string principal)
        {
            Console.WriteLine();

            Console.WriteLine(
                "---------- ABUSE GUIDANCE ----------");

            Console.WriteLine(
                $"Permission : {permission}");

            Console.WriteLine(
                $"Principal  : {principal}");

            Console.WriteLine(
                $"Target     : {target}");

            Console.WriteLine();

            switch (permission)
            {
                // =====================================================
                // GenericAll
                // =====================================================

                case "GenericAll":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Full control over the target object.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Use the available control to perform a " +
                        "security-sensitive operation on the target.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' set password " +
                        "'<target_user>' '<NewPass123!>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainUserPassword -Identity '<target_user>' " +
                        "-NewPassword (ConvertTo-SecureString " +
                        "'<NewPass123!>' -AsPlainText -Force)");

                    break;


                // =====================================================
                // GenericWrite
                // =====================================================

                case "GenericWrite":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows modification of writable attributes " +
                        "on the target object.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Identify and modify a security-sensitive " +
                        "writable attribute.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' set object " +
                        "'<target_object>' '<attribute>' -v '<value>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainObject -Identity '<target_object>' " +
                        "-Set @{'<attribute>'='<value>'}");

                    break;


                // =====================================================
                // WriteDacl
                // =====================================================

                case "WriteDacl":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows modification of the target object's DACL.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Modify the DACL to grant additional permissions " +
                        "to a controlled principal.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  Impacket dacledit.py");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  dacledit.py -action grant -principal '<principal>' " +
                        "-rights GenericAll -target '<target_object>' " +
                        "'domain.local/<user>:<pass>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Add-DomainObjectAcl -TargetIdentity '<target_object>' " +
                        "-PrincipalIdentity '<principal>' -Rights All");

                    break;


                // =====================================================
                // WriteOwner
                // =====================================================

                case "WriteOwner":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows changing the owner of the target object.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Change the owner to a controlled principal and " +
                        "then modify the object's DACL.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  Impacket owneredit.py");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  owneredit.py -action write -new-owner '<principal>' " +
                        "-target '<target_object>' " +
                        "'domain.local/<user>:<pass>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainObjectOwner -Identity '<target_object>' " +
                        "-OwnerIdentity '<principal>'");

                    break;


                // =====================================================
                // ForceChangePassword
                // =====================================================

                case "ForceChangePassword":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows resetting the target user's password " +
                        "without knowing the current password.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Reset the target account password and authenticate " +
                        "using the new credentials.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' set password " +
                        "'<target_user>' '<NewPass123!>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainUserPassword -Identity '<target_user>' " +
                        "-NewPassword (ConvertTo-SecureString " +
                        "'<NewPass123!>' -AsPlainText -Force)");

                    break;


                // =====================================================
                // DS-Replication-Get-Changes
                // =====================================================

                case "DS-Replication-Get-Changes":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Provides a directory-replication permission " +
                        "used in a potential DCSync path.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Check whether the principal also has " +
                        "DS-Replication-Get-Changes-All.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  Impacket");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  Verify the required replication-right combination " +
                        "before attempting DCSync.");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Get-DomainObjectAcl -SearchBase " +
                        "'DC=domain,DC=local'");

                    break;


                // =====================================================
                // DS-Replication-Get-Changes-All
                // =====================================================

                case "DS-Replication-Get-Changes-All":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Provides a replication permission contributing " +
                        "to a potential DCSync capability.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Confirm Get-Changes is also present, then perform " +
                        "an authorized DCSync assessment.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  Impacket secretsdump.py");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  secretsdump.py '<domain>/<user>:<pass>@<DC_IP>' " +
                        "-just-dc-user '<target_user>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  Mimikatz");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  lsadump::dcsync /domain:<domain.local> " +
                        "/user:<target_user>");

                    break;


                // =====================================================
                // DS-Replication-Get-Changes-In-Filtered-Set
                // =====================================================

                case "DS-Replication-Get-Changes-In-Filtered-Set":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows replication of attributes in the " +
                        "RODC filtered attribute set.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Review this together with the principal's " +
                        "other replication permissions.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  Impacket");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  Review the complete replication-right combination " +
                        "before attempting replication operations.");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Get-DomainObjectAcl -SearchBase " +
                        "'DC=domain,DC=local'");

                    break;


                // =====================================================
                // AddMember
                // =====================================================

                case "AddMember":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows adding a principal to the target group.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Add a controlled principal to the group to " +
                        "inherit its permissions.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' add groupMember " +
                        "'<target_group>' '<member>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Add-DomainGroupMember -Identity '<target_group>' " +
                        "-Members '<member>'");

                    break;


                // =====================================================
                // WriteSPN
                // =====================================================

                case "WriteSPN":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows modification of the target object's " +
                        "servicePrincipalName attribute.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Modify the SPN on a suitable account and assess " +
                        "the resulting Kerberos implications.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' set object '<target_user>' " +
                        "servicePrincipalName -v '<SPN>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainObject -Identity '<target_user>' " +
                        "-Set @{'servicePrincipalName'='<SPN>'}");

                    break;


                // =====================================================
                // WriteUserAccountControl
                // =====================================================

                case "WriteUserAccountControl":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows modification of the userAccountControl " +
                        "attribute.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Modify a security-relevant UAC flag and assess " +
                        "its authentication impact.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' set object '<target_user>' " +
                        "userAccountControl -v '<value>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainObject -Identity '<target_user>' " +
                        "-Set @{'userAccountControl'='<value>'}");

                    break;


                // =====================================================
                // WriteAllowedToAct
                // =====================================================

                case "WriteAllowedToAct":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows modification of the RBCD configuration " +
                        "on a computer account.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Modify msDS-AllowedToActOnBehalfOfOtherIdentity " +
                        "to configure RBCD.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' add rbcd " +
                        "'<target_computer$>' '<delegate_computer$>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine("  PowerView");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Set-DomainObject -Identity '<target_computer$>' " +
                        "-Set @{'msDS-AllowedToActOnBehalfOfOtherIdentity'=" +
                        "'<security_descriptor>'}");

                    break;


                // =====================================================
                // CreateChild
                // =====================================================

                case "CreateChild":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows creation of permitted child objects " +
                        "under the target container or OU.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Create an allowed child object and assess " +
                        "whether it creates a privilege path.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' add computer '<computer$>' " +
                        "'<Password123!>' --container " +
                        "'OU=TargetOU,DC=domain,DC=local'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine(
                        "  PowerShell ActiveDirectory module");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  New-ADUser -Name '<new_user>' " +
                        "-Path 'OU=TargetOU,DC=domain,DC=local'");

                    break;


                // =====================================================
                // DeleteChild
                // =====================================================

                case "DeleteChild":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows deletion of applicable child objects " +
                        "under the target container.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Delete an authorized test child object and " +
                        "assess the resulting impact.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  bloodyAD");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  bloodyAD --host <DC_IP> -d 'domain.local' " +
                        "-u '<user>' -p '<pass>' remove object '<target_child>'");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine(
                        "  PowerShell ActiveDirectory module");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Remove-ADObject -Identity '<target_child_DN>' " +
                        "-Confirm:$false");

                    break;


                // =====================================================
                // ReadGMSAPassword
                // =====================================================

                case "ReadGMSAPassword":

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  Allows an authorized principal to retrieve " +
                        "the managed password of a gMSA.");

                    Console.WriteLine();

                    Console.WriteLine("Abuse Step:");
                    Console.WriteLine(
                        "  Verify that the principal is authorized to " +
                        "retrieve the gMSA managed password.");

                    Console.WriteLine();

                    Console.WriteLine("Linux Tool:");
                    Console.WriteLine("  gMSADumper");

                    Console.WriteLine("Linux Command:");
                    Console.WriteLine(
                        "  gMSADumper.py -u '<user>' -p '<pass>' " +
                        "-d 'domain.local' -dc-ip <DC_IP>");

                    Console.WriteLine();

                    Console.WriteLine("Windows Tool:");
                    Console.WriteLine(
                        "  PowerShell ActiveDirectory module");

                    Console.WriteLine("Windows Command:");
                    Console.WriteLine(
                        "  Get-ADServiceAccount -Identity '<gmsa_account$>' " +
                        "-Properties PrincipalsAllowedToRetrieveManagedPassword");

                    break;


                // =====================================================
                // Default
                // =====================================================

                default:

                    Console.WriteLine("Explanation:");
                    Console.WriteLine(
                        "  No abuse guidance is currently available " +
                        "for this permission.");

                    break;
            }

            Console.WriteLine();

            Console.WriteLine(
                "------------------------------------------");

            Console.WriteLine();
        }


        // =========================================================
        // INTERESTING ACL ENUMERATION
        // =========================================================

        static void EnumerateInterestingACLs()
        {
            try
            {
                graphEdges.Clear();

                Console.WriteLine();
                Console.WriteLine(
                    "==========================================");

                Console.WriteLine(
                    "        INTERESTING ACL DETECTION");

                Console.WriteLine(
                    "==========================================");

                Console.WriteLine();

                using (DirectoryEntry root =
                    GetRootDSE())
                {
                    string baseDn =
                        root.Properties[
                            "defaultNamingContext"]
                            .Value.ToString();

                    using (DirectoryEntry domain =
                        new DirectoryEntry(
                            $"LDAP://{baseDn}"))
                    {
                        using (DirectorySearcher searcher =
                            new DirectorySearcher(domain))
                        {
                            searcher.Filter =
                                "(objectClass=*)";

                            searcher.PropertiesToLoad.Add(
                                "distinguishedName");

                            searcher.PageSize = 500;

                            SearchResultCollection results =
                                searcher.FindAll();

                            Console.WriteLine(
                                $"[+] Objects found: {results.Count}");

                            int objectNumber = 1;

                            foreach (
                                SearchResult result
                                in results)
                            {
                                string distinguishedName =
                                    GetProperty(
                                        result,
                                        "distinguishedName");

                                if (string.IsNullOrEmpty(
                                    distinguishedName))
                                {
                                    continue;
                                }

                                try
                                {
                                    ActiveDirectorySecurity security =
                                        GetSecurityDescriptor(
                                            distinguishedName);

                                    AuthorizationRuleCollection rules =
                                        security.GetAccessRules(
                                            true,
                                            true,
                                            typeof(SecurityIdentifier));

                                    foreach (
                                        ActiveDirectoryAccessRule rule
                                        in rules)
                                    {
                                        if (rule.AccessControlType !=
                                            AccessControlType.Allow)
                                        {
                                            continue;
                                        }

                                        if (!IsInterestingRule(rule))
                                        {
                                            continue;
                                        }

                                        Console.WriteLine();
                                        Console.WriteLine(
                                            "==========================================");

                                        Console.WriteLine(
                                            $"OBJECT {objectNumber}");

                                        Console.WriteLine(
                                            $"Target : {distinguishedName}");

                                        Console.WriteLine(
                                            $"Principal : " +
                                            $"{rule.IdentityReference}");

                                        Console.WriteLine(
                                            $"Rights : " +
                                            $"{rule.ActiveDirectoryRights}");

                                        Console.WriteLine(
                                            $"ObjectType : {rule.ObjectType}");

                                        Console.WriteLine(
                                            $"Inherited : {rule.IsInherited}");

                                        DetectInterestingACL(
                                            rule,
                                            distinguishedName);

                                        AddGraphEdge(
                                            rule,
                                            distinguishedName);
                                    }

                                    if (IsGMSA(
                                        distinguishedName))
                                    {
                                        EnumerateInterestingGMSA(
                                            distinguishedName);
                                    }
                                }
                                catch
                                {
                                    continue;
                                }

                                objectNumber++;
                            }
                        }
                    }
                }

                ShowConsoleGraph();
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] Interesting ACL search failed: " +
                    $"{ex.Message}");
            }
        }


        // =========================================================
        // INTERESTING RULE CHECK
        // =========================================================

        static bool IsInterestingRule(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;


            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
                return true;


            // Only interesting WriteProperty attributes
            if (IsInterestingWriteProperty(rule))
                return true;


            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
                return true;

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
                return true;


            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == ResetPasswordGuid)
                return true;

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesGuid)
                return true;

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesAllGuid)
                return true;

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType ==
                GetChangesInFilteredSetGuid)
                return true;

            return false;
        }


        // =========================================================
        // INTERESTING gMSA
        // =========================================================

        static void EnumerateInterestingGMSA(
            string distinguishedName)
        {
            try
            {
                AuthorizationRuleCollection rules =
                    GetGmsaMembershipRules(
                        distinguishedName);

                if (rules == null)
                    return;

                foreach (
                    ActiveDirectoryAccessRule rule
                    in rules)
                {
                    if (rule.AccessControlType !=
                        AccessControlType.Allow)
                        continue;

                    if (!GmsaPasswordReadMatches(rule))
                        continue;

                    string principal =
                        ResolveIdentityReference(rule.IdentityReference);

                    Console.WriteLine();
                    Console.WriteLine(
                        "==========================================");

                    Console.WriteLine(
                        "          gMSA PASSWORD ACCESS");

                    Console.WriteLine(
                        "==========================================");

                    Console.WriteLine(
                        $"Target    : {distinguishedName}");

                    Console.WriteLine(
                        $"Principal : {principal}");

                    Console.WriteLine(
                        $"Rights    : {rule.ActiveDirectoryRights}");

                    PrintFinding(
                        "HIGH",
                        "ReadGMSAPassword",
                        "Principal can access the managed " +
                        "credential of this gMSA.");

                    ShowAbuseGuidance(
                        "ReadGMSAPassword",
                        distinguishedName,
                        principal);

                    AddGmsaGraphEdge(
                        rule,
                        distinguishedName);
                }
            }
            catch
            {
                // Ignore individual gMSA failures
            }
        }


        // =========================================================
        // PERMISSION SEARCH
        // =========================================================

        static void SearchPermission(
            string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine(
                    "[-] Permission required.");

                Console.WriteLine(
                    "[*] Usage: ACEHound permission <permission>");

                return;
            }

            string permission = args[1];

            graphEdges.Clear();

            Console.WriteLine();
            Console.WriteLine(
                $"[*] Searching for: {permission}");

            Console.WriteLine();

            try
            {
                using (DirectoryEntry root =
                    GetRootDSE())
                {
                    string baseDn =
                        root.Properties[
                            "defaultNamingContext"]
                            .Value.ToString();

                    SearchACLByPermission(
                        baseDn,
                        permission);
                }

                ShowConsoleGraph();
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[-] Permission search failed: {ex.Message}");
            }
        }


        // =========================================================
        // SEARCH ACL BY PERMISSION
        // =========================================================

        static void SearchACLByPermission(
            string baseDn,
            string permission)
        {
            using (DirectoryEntry domain =
                new DirectoryEntry(
                    $"LDAP://{baseDn}"))
            {
                using (DirectorySearcher searcher =
                    new DirectorySearcher(domain))
                {
                    searcher.Filter =
                        "(objectClass=*)";

                    searcher.PropertiesToLoad.Add(
                        "distinguishedName");

                    searcher.PageSize = 500;

                    SearchResultCollection results =
                        searcher.FindAll();

                    int matchCount = 0;


                    foreach (
                        SearchResult result
                        in results)
                    {
                        string distinguishedName =
                            GetProperty(
                                result,
                                "distinguishedName");

                        if (string.IsNullOrEmpty(
                            distinguishedName))
                            continue;


                        // =================================================
                        // gMSA
                        // =================================================

                        if (permission.Equals(
                            "ReadGMSAPassword",
                            StringComparison.OrdinalIgnoreCase))
                        {
                            if (!IsGMSA(
                                distinguishedName))
                                continue;

                            AuthorizationRuleCollection
                                gmsaRules =
                                GetGmsaMembershipRules(
                                    distinguishedName);

                            if (gmsaRules == null)
                                continue;

                            foreach (
                                ActiveDirectoryAccessRule rule
                                in gmsaRules)
                            {
                                if (rule.AccessControlType !=
                                    AccessControlType.Allow)
                                    continue;

                                if (!GmsaPasswordReadMatches(rule))
                                    continue;

                                matchCount++;

                                string principal =
                                    ResolveIdentityReference(rule.IdentityReference);

                                Console.WriteLine();
                                Console.WriteLine(
                                    $"MATCH {matchCount}");

                                Console.WriteLine(
                                    $"Target    : {distinguishedName}");

                                Console.WriteLine(
                                    $"Principal : {principal}");

                                Console.WriteLine(
                                    $"Rights    : " +
                                    $"{rule.ActiveDirectoryRights}");

                                PrintFinding(
                                    "HIGH",
                                    "ReadGMSAPassword",
                                    "Can access the managed " +
                                    "credential of this gMSA.");

                                ShowAbuseGuidance(
                                    "ReadGMSAPassword",
                                    distinguishedName,
                                    principal);

                                AddGmsaGraphEdge(
                                    rule,
                                    distinguishedName);
                            }

                            continue;
                        }


                        // =================================================
                        // NORMAL ACL
                        // =================================================

                        try
                        {
                            ActiveDirectorySecurity security =
                                GetSecurityDescriptor(
                                    distinguishedName);

                            AuthorizationRuleCollection rules =
                                security.GetAccessRules(
                                    true,
                                    true,
                                    typeof(SecurityIdentifier));

                            foreach (
                                ActiveDirectoryAccessRule rule
                                in rules)
                            {
                                if (rule.AccessControlType !=
                                    AccessControlType.Allow)
                                    continue;

                                if (!PermissionMatches(
                                    rule,
                                    permission))
                                    continue;

                                matchCount++;

                                string principal =
                                    ResolveIdentityReference(rule.IdentityReference);

                                Console.WriteLine();
                                Console.WriteLine(
                                    $"==========================================");

                                Console.WriteLine(
                                    $"MATCH {matchCount}");

                                Console.WriteLine(
                                    $"Target    : {distinguishedName}");

                                Console.WriteLine(
                                    $"Principal : {principal}");

                                Console.WriteLine(
                                    $"Rights    : " +
                                    $"{rule.ActiveDirectoryRights}");

                                Console.WriteLine(
                                    $"ObjectType: {rule.ObjectType}");

                                Console.WriteLine(
                                    $"Inherited : {rule.IsInherited}");

                                Console.WriteLine();

                                ParseACE(rule);

                                AnalyzePermission(rule);

                                string guidancePermission =
                                    GetGuidancePermission(rule);

                                if (!string.IsNullOrEmpty(
                                    guidancePermission))
                                {
                                    ShowAbuseGuidance(
                                        guidancePermission,
                                        distinguishedName,
                                        principal);
                                }

                                AddGraphEdge(
                                    rule,
                                    distinguishedName);
                            }
                        }
                        catch
                        {
                            continue;
                        }
                    }

                    Console.WriteLine();

                    Console.WriteLine(
                        $"[+] Matching ACEs: {matchCount}");
                }
            }
        }


        // =========================================================
        // GET GUIDANCE PERMISSION
        // =========================================================

        static string GetGuidancePermission(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;


            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                return "GenericAll";

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
                return "WriteDacl";

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
                return "WriteOwner";

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
                return "GenericWrite";


            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0)
            {
                if (objectType == ResetPasswordGuid)
                    return "ForceChangePassword";

                if (objectType == GetChangesGuid)
                    return "DS-Replication-Get-Changes";

                if (objectType == GetChangesAllGuid)
                    return "DS-Replication-Get-Changes-All";

                if (objectType ==
                    GetChangesInFilteredSetGuid)
                    return
                        "DS-Replication-Get-Changes-In-Filtered-Set";
            }


            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0)
            {
                if (objectType == MemberAttributeGuid)
                    return "AddMember";

                if (objectType == ServicePrincipalNameGuid)
                    return "WriteSPN";

                if (objectType == UserAccountControlGuid)
                    return "WriteUserAccountControl";

                if (objectType == AllowedToActGuid)
                    return "WriteAllowedToAct";
            }


            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
                return "CreateChild";

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
                return "DeleteChild";

            return string.Empty;
        }


        // =========================================================
        // PERMISSION MATCH
        // =========================================================

        static bool PermissionMatches(
            ActiveDirectoryAccessRule rule,
            string permission)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;


            if (permission.Equals(
                "GenericAll",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.GenericAll) != 0;
            }


            if (permission.Equals(
                "GenericWrite",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.GenericWrite) != 0;
            }


            if (permission.Equals(
                "GenericRead",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.GenericRead) != 0;
            }


            if (permission.Equals(
                "WriteDacl",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.WriteDacl) != 0;
            }


            if (permission.Equals(
                "WriteOwner",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.WriteOwner) != 0;
            }


            if (permission.Equals(
                "WriteProperty",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.WriteProperty) != 0;
            }


            if (permission.Equals(
                "ReadProperty",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.ReadProperty) != 0;
            }


            if (permission.Equals(
                "CreateChild",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.CreateChild) != 0;
            }


            if (permission.Equals(
                "DeleteChild",
                StringComparison.OrdinalIgnoreCase))
            {
                return (rights &
                    ActiveDirectoryRights.DeleteChild) != 0;
            }


            if (permission.Equals(
                "ForceChangePassword",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.ExtendedRight) != 0
                    &&
                    objectType == ResetPasswordGuid;
            }


            if (permission.Equals(
                "DS-Replication-Get-Changes",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.ExtendedRight) != 0
                    &&
                    objectType == GetChangesGuid;
            }


            if (permission.Equals(
                "DS-Replication-Get-Changes-All",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.ExtendedRight) != 0
                    &&
                    objectType == GetChangesAllGuid;
            }


            if (permission.Equals(
                "DS-Replication-Get-Changes-In-Filtered-Set",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.ExtendedRight) != 0
                    &&
                    objectType ==
                    GetChangesInFilteredSetGuid;
            }


            if (permission.Equals(
                "AddMember",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.WriteProperty) != 0
                    &&
                    objectType == MemberAttributeGuid;
            }


            if (permission.Equals(
                "WriteSPN",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.WriteProperty) != 0
                    &&
                    objectType == ServicePrincipalNameGuid;
            }


            if (permission.Equals(
                "WriteUserAccountControl",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.WriteProperty) != 0
                    &&
                    objectType == UserAccountControlGuid;
            }


            if (permission.Equals(
                "WriteAllowedToAct",
                StringComparison.OrdinalIgnoreCase))
            {
                return
                    (rights &
                     ActiveDirectoryRights.WriteProperty) != 0
                    &&
                    objectType == AllowedToActGuid;
            }


            Console.WriteLine(
                $"[-] Unknown permission: {permission}");

            return false;
        }


        // =========================================================
        // GRAPH EDGE
        // =========================================================

        static void AddGraphEdge(
            ActiveDirectoryAccessRule rule,
            string target)
        {
            string principal =
                ResolveIdentityReference(rule.IdentityReference);

            string permission =
                GetGraphPermission(rule);

            if (string.IsNullOrEmpty(permission))
                return;

            graphEdges.Add(
                new GraphEdge
                {
                    Principal = principal,
                    Permission = permission,
                    Target = target
                });
        }


        // =========================================================
        // gMSA GRAPH EDGE
        // =========================================================

        static void AddGmsaGraphEdge(
            ActiveDirectoryAccessRule rule,
            string target)
        {
            string principal =
                ResolveIdentityReference(rule.IdentityReference);

            graphEdges.Add(
                new GraphEdge
                {
                    Principal = principal,
                    Permission = "ReadGMSAPassword",
                    Target = target
                });
        }


        // =========================================================
        // GRAPH PERMISSION
        // =========================================================

        static string GetGraphPermission(
            ActiveDirectoryAccessRule rule)
        {
            ActiveDirectoryRights rights =
                rule.ActiveDirectoryRights;

            Guid objectType =
                rule.ObjectType;


            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == ResetPasswordGuid)
                return "ForceChangePassword";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesGuid)
                return "Get-Changes";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesAllGuid)
                return "Get-Changes-All";

            if ((rights &
                ActiveDirectoryRights.ExtendedRight) != 0 &&
                objectType == GetChangesInFilteredSetGuid)
                return "Get-Changes-Filtered";


            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == MemberAttributeGuid)
                return "AddMember";


            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == ServicePrincipalNameGuid)
                return "WriteSPN";


            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == UserAccountControlGuid)
                return "WriteUserAccountControl";


            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0 &&
                objectType == AllowedToActGuid)
                return "WriteAllowedToAct";


            if ((rights &
                ActiveDirectoryRights.GenericAll) != 0)
                return "GenericAll";

            if ((rights &
                ActiveDirectoryRights.GenericWrite) != 0)
                return "GenericWrite";

            if ((rights &
                ActiveDirectoryRights.WriteDacl) != 0)
                return "WriteDacl";

            if ((rights &
                ActiveDirectoryRights.WriteOwner) != 0)
                return "WriteOwner";

            if ((rights &
                ActiveDirectoryRights.WriteProperty) != 0)
                return "WriteProperty";

            if ((rights &
                ActiveDirectoryRights.CreateChild) != 0)
                return "CreateChild";

            if ((rights &
                ActiveDirectoryRights.DeleteChild) != 0)
                return "DeleteChild";

            if ((rights &
                ActiveDirectoryRights.GenericRead) != 0)
                return "GenericRead";

            if ((rights &
                ActiveDirectoryRights.ReadProperty) != 0)
                return "ReadProperty";

            return string.Empty;
        }


        // =========================================================
        // CONSOLE GRAPH
        // =========================================================

        static void ShowConsoleGraph()
        {
            Console.WriteLine();
            Console.WriteLine(
                "==========================================");

            Console.WriteLine(
                "          ACL RELATIONSHIP GRAPH");

            Console.WriteLine(
                "==========================================");

            Console.WriteLine();

            if (graphEdges.Count == 0)
            {
                Console.WriteLine(
                    "[+] No graph relationships found.");

                return;
            }

            foreach (GraphEdge edge in graphEdges)
            {
                Console.WriteLine(
                    $"[{edge.Principal}]");

                Console.WriteLine(
                    "        |");

                Console.WriteLine(
                    $"        | {edge.Permission}");

                Console.WriteLine(
                    "        v");

                Console.WriteLine(
                    $"[{edge.Target}]");

                Console.WriteLine();
            }

            Console.WriteLine(
                $"[+] Graph relationships: {graphEdges.Count}");

            Console.WriteLine();
        }


        // =========================================================
        // SID / IDENTITY RESOLUTION
        // =========================================================

        static string ResolveIdentityReference(
            IdentityReference identityReference)
        {
            if (identityReference == null)
                return string.Empty;

            try
            {
                // Access rules are requested as SecurityIdentifier objects.
                // Translate the SID into its readable NT account name.
                SecurityIdentifier sid =
                    identityReference as SecurityIdentifier;

                if (sid != null)
                {
                    try
                    {
                        NTAccount account =
                            (NTAccount)sid.Translate(
                                typeof(NTAccount));

                        if (account != null &&
                            !string.IsNullOrEmpty(account.Value))
                        {
                            return account.Value;
                        }
                    }
                    catch
                    {
                        // Translation can fail when the SID cannot be
                        // resolved by the current Windows security context.
                    }

                    // Always keep the original SID as a safe fallback.
                    return sid.Value;
                }

                return identityReference.ToString();
            }
            catch
            {
                return identityReference.ToString();
            }
        }


        // =========================================================
        // GET PROPERTY
        // =========================================================

        static string GetProperty(
            SearchResult result,
            string propertyName)
        {
            if (!result.Properties.Contains(
                propertyName))
                return string.Empty;

            if (result.Properties[propertyName].Count == 0)
                return string.Empty;

            return result.Properties[
                propertyName][0].ToString();
        }


        // =========================================================
        // LDAP ESCAPING
        // =========================================================

        static string EscapeLDAP(
            string value)
        {
            return value
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }


        // =========================================================
        // MAIN
        // =========================================================

        static void Main(
            string[] args)
        {
            if (args.Length == 0)
            {
                ShowHelp();
                return;
            }

            string command =
                args[0].ToLower();

            switch (command)
            {
                case "--help":

                    ShowHelp();

                    break;


                case "--version":

                    ShowVersion();

                    break;


                case "interesting":

                    EnumerateInterestingACLs();

                    break;


                case "user":

                    SearchUser(args);

                    break;


                case "permission":

                    SearchPermission(args);

                    break;


                default:

                    Console.WriteLine(
                        $"[-] Unknown command: {args[0]}");

                    Console.WriteLine(
                        "[*] Use 'ACEHound --help' for help.");

                    break;
            }
        }
    }
}


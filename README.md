# 🔐 MFA Disabled User Audit with PowerShell and Microsoft Graph

This PowerShell tool connects to Microsoft Graph to identify Azure AD users who do **not** have Multi-Factor Authentication (MFA) configured.

Identifying accounts without MFA is a critical security control for modern cloud environments. This script demonstrates practical **IAM**, **security auditing**, and **automation** using Microsoft Graph and PowerShell.

---

## ✅ Prerequisites

- PowerShell 7+ (recommended)  
- Microsoft Graph PowerShell Module  
- Required Microsoft Graph permissions:
  - `User.Read.All`
  - `Directory.Read.All`
  - `AuthenticationMethod.Read.All`

> ⚠️ The script is read-only and **does not modify any user accounts**.

---

## ▶️ Usage

Run the script and display results in the console:

```powershell
.\Get-MFADisabledUsers.ps1

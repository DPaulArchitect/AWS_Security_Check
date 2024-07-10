import boto3


class IAMAuditor:
    def __init__(self):
        self.iam = boto3.client('iam')

    def list_iam_users(self):
        users = self.iam.list_users()
        return users['Users']

    def check_mfa_enabled(self, user_name):
        mfa_devices = self.iam.list_mfa_devices(UserName=user_name)
        return len(mfa_devices['MFADevices']) > 0

    def audit_iam_users(self):
        users = self.list_iam_users()
        report = "IAM Users Security Report\n\n"
        for user in users:
            user_name = user['UserName']
            mfa_enabled = self.check_mfa_enabled(user_name)
            if not mfa_enabled:
                report += f"User '{user_name}' does not have MFA enabled.\n"

        if report == "IAM Users Security Report\n\n":
            report += "All users have MFA enabled.\n"

        return report

import tkinter as tk
from tkinter import ttk, messagebox
import boto3
from aws_security_checker import S3Auditor
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

class AWSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AWS Security Checker")
        
        # AWS Credentials input
        self.access_key_label = tk.Label(root, text="AWS Access Key:")
        self.access_key_label.grid(row=0, column=0, padx=10, pady=5)
        self.access_key_entry = tk.Entry(root, width=40)
        self.access_key_entry.grid(row=0, column=1, padx=10, pady=5)

        self.secret_key_label = tk.Label(root, text="AWS Secret Key:")
        self.secret_key_label.grid(row=1, column=0, padx=10, pady=5)
        self.secret_key_entry = tk.Entry(root, show="*", width=40)
        self.secret_key_entry.grid(row=1, column=1, padx=10, pady=5)

        self.region_label = tk.Label(root, text="AWS Region:")
        self.region_label.grid(row=2, column=0, padx=10, pady=5)
        self.region_entry = tk.Entry(root, width=40)
        self.region_entry.grid(row=2, column=1, padx=10, pady=5)

        self.connect_button = ttk.Button(root, text="Connect", command=self.connect_aws)
        self.connect_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.text_area = tk.Text(root, height=20, width=80)
        self.text_area.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

    def connect_aws(self):
        access_key = self.access_key_entry.get()
        secret_key = self.secret_key_entry.get()
        region = self.region_entry.get()

        try:
            self.s3_auditor = S3Auditor(access_key, secret_key, region)
            report = self.s3_auditor.audit_buckets()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, report)
        except NoCredentialsError:
            messagebox.showerror("Error", "AWS credentials not found.")
        except PartialCredentialsError:
            messagebox.showerror("Error", "Incomplete AWS credentials found.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

class S3Auditor:
    def __init__(self, access_key, secret_key, region):
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region
        )

    def list_s3_buckets(self):
        response = self.s3.list_buckets()
        return [bucket['Name'] for bucket in response['Buckets']]

    def check_bucket_public_access(self, bucket_name):
        public_access = False

        # Check bucket policy
        try:
            policy = self.s3.get_bucket_policy(Bucket=bucket_name)
            if 'Public' in policy['Policy']:
                public_access = True
        except self.s3.exceptions.NoSuchBucketPolicy:
            pass

        # Check bucket ACL
        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl['Grants']:
            if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                public_access = True

        return public_access

    def generate_report(self, buckets_with_issues):
        report = "S3 Bucket Security Report\n\n"
        if buckets_with_issues:
            report += "Publicly Accessible Buckets:\n"
            for bucket in buckets_with_issues:
                report += f"- {bucket}\n"
            report += "\nRecommendation: Restrict public access to these buckets.\n"
        else:
            report += "All buckets are secure.\n"
        return report

    def audit_buckets(self):
        buckets = self.list_s3_buckets()
        if not buckets:
            raise Exception("No buckets found or unable to retrieve buckets.")

        buckets_with_issues = []
        for bucket in buckets:
            if self.check_bucket_public_access(bucket):
                buckets_with_issues.append(bucket)

        return self.generate_report(buckets_with_issues)

if __name__ == "__main__":
    root = tk.Tk()
    app = AWSApp(root)
    root.mainloop()

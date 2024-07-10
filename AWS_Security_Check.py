import tkinter as tk
from tkinter import ttk, messagebox
from aws_security_checker import S3Auditor, IAMAuditor, EC2Auditor, RDSAuditor
from botocore.exceptions import NoCredentialsError, PartialCredentialsError


class AWSApp:

    def __init__(self, root):
        self.root = root
        self.root.title("AWS Security Checker")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(8, weight=1)

        self.access_key_label = tk.Label(root, text="AWS Access Key:")
        self.access_key_label.grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.access_key_entry = tk.Entry(root, width=40)
        self.access_key_entry.grid(row=0, column=1, padx=10, pady=5, sticky='ew')

        self.secret_key_label = tk.Label(root, text="AWS Secret Key:")
        self.secret_key_label.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        self.secret_key_entry = tk.Entry(root, show="*", width=40)
        self.secret_key_entry.grid(row=1, column=1, padx=10, pady=5, sticky='ew')

        self.region_label = tk.Label(root, text="AWS Region:")
        self.region_label.grid(row=2, column=0, padx=10, pady=5, sticky='w')
        self.region_entry = tk.Entry(root, width=40)
        self.region_entry.grid(row=2, column=1, padx=10, pady=5, sticky='ew')

        self.connect_button = ttk.Button(root, text="Connect", command=self.connect_aws)
        self.connect_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

        self.s3_auditor = None
        self.iam_auditor = None
        self.ec2_auditor = None
        self.rds_auditor = None

        self.s3_audit_button = ttk.Button(root, text="Audit S3 Buckets", command=self.audit_s3)
        self.s3_audit_button.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        self.iam_audit_button = ttk.Button(root, text="Audit IAM Users", command=self.audit_iam)
        self.iam_audit_button.grid(row=4, column=1, columnspan=2, padx=10, pady=10)

        self.ec2_audit_button = ttk.Button(root, text="Audit EC2 Security Groups", command=self.audit_ec2)
        self.ec2_audit_button.grid(row=5, column=0, columnspan=2, padx=10, pady=10)

        self.rds_audit_button = ttk.Button(root, text="Audit RDS Instances", command=self.audit_rds)
        self.rds_audit_button.grid(row=5, column=1, columnspan=2, padx=10, pady=10)

        self.text_area = tk.Text(root, height=20, width=80)
        self.text_area.grid(row=8, column=0, columnspan=2, padx=10, pady=10, sticky='nsew')

    def connect_aws(self):
        access_key = self.access_key_entry.get()
        secret_key = self.secret_key_entry.get()
        region = self.region_entry.get()

        try:
            self.s3_auditor = S3Auditor(access_key, secret_key, region)
            self.iam_auditor = IAMAuditor()
            self.ec2_auditor = EC2Auditor()
            self.rds_auditor = RDSAuditor()
            messagebox.showinfo("Success", "Connected to AWS successfully.")
        except NoCredentialsError:
            messagebox.showerror("Error", "AWS credentials not found.")
        except PartialCredentialsError:
            messagebox.showerror("Error", "Incomplete AWS credentials found.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def audit_s3(self):
        if self.s3_auditor is None:
            messagebox.showwarning("Warning", "Please connect to AWS first.")
            return

        try:
            report = self.s3_auditor.audit_buckets()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, report)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def audit_iam(self):
        if self.iam_auditor is None:
            messagebox.showwarning("Warning", "Please connect to AWS first.")
            return

        try:
            report = self.iam_auditor.audit_iam_users()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, report)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def audit_ec2(self):
        if self.ec2_auditor is None:
            messagebox.showwarning("Warning", "Please connect to AWS first.")
            return

        try:
            report = self.ec2_auditor.audit_security_groups()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, report)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def audit_rds(self):
        if self.rds_auditor is None:
            messagebox.showwarning("Warning", "Please connect to AWS first.")
            return

        try:
            report = self.rds_auditor.audit_rds_instances()
            self.text_area.delete(1.0, tk.END)
            self.text_area.insert(tk.END, report)
        except Exception as e:
            messagebox.showerror("Error", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = AWSApp(root)
    root.mainloop()

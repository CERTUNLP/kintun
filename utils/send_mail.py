#!/bin/python3
#
# This file is part of the Kintun - Restful Vulnerability Scanner
#
# (c) CERT UNLP <support@cert.unlp.edu.ar>
#
# This source file is subject to the GPL v3.0 license that is bundled
# with this source code in the file LICENSE.
#
import gnupg, smtplib, email
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pprint import pprint

class MailLog:
    def __init__(self,
                name = 'Kintun',
                me = 'kintun@kintun-cert.unlp.edu.ar',
                recipients_error = ['apaturlanne@cert.unlp.edu.ar'],
                recipients_log = ['apaturlanne@cert.unlp.edu.ar'],
                recipients = ['apaturlanne@cert.unlp.edu.ar'],
                subject = '[{0}]{1} Reporte {0}',
                body = 'Le enviamos un reporte automático. {0}\n\nCERT-UNLP',
                mail_server = '163.10.40.194',
                file_name = "{0}.txt",
                detail=""):
        self.name = name
        self.me = me
        self.recipients_error = recipients_error
        self.recipients_log = recipients_log
        self.recipients = recipients
        self.subject = subject
        self.body = body.format(detail)
        self.mail_server = mail_server
        self.file_name = file_name.format(name)

    def __init__(self, dictionary):
        for k, v in dictionary.items():
            setattr(self, k, v)

    def getSubject(self, slug=""):
        return self.subject.format(self.name, slug)

    def create_mime_multipart(self, me, recipients, subject):
        # Create the container (msg) email message.
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = me
        msg['To'] = ', '.join(recipients)
        return msg

    def set_body(self, msg, body):
        #cuerpo del mensaje
        msg.preamble = ''
        msg.attach(MIMEText(body,'plaintext'))
        return msg

    def encrypt_for(self, recipients, filename, outfilename, gpgfolder):#, recipients_keys):
        #Encriptacion del reporte adjunto
        gpg = gnupg.GPG(gnupghome=gpgfolder)
    #    data = open(recipients_keys).read()
    #    import_result = gpg.import_keys(data)
        #public_keys = gpg.list_keys()
        #pprint(public_keys)
        afile = open(filename, "rb")
        encrypted_ascii_data = gpg.encrypt_file(afile, recipients, always_trust=True, output=outfilename)

    def sanitize(self, str):
        return ''.join(e for e in str.replace(" ","_") if e.isalnum() or e in [".","_","-"])

    def attach_gpg_file(self, msg, filename, sendfilename):
        #adjuntar el archivo
        fileMsg = email.mime.base.MIMEBase('application','pgp-encrypted')
        fileMsg.set_payload(open(filename).read())
        email.encoders.encode_base64(fileMsg)
        fileMsg.add_header('Content-Disposition','attachment;filename='+self.sanitize(sendfilename))
        msg.attach(fileMsg)
        return msg

    def attach_file(self, msg, sendfilename, content):
        #adjuntar el archivo
        fileMsg = email.mime.base.MIMEBase('application','text/plain')
        fileMsg.set_payload(content)
        email.encoders.encode_base64(fileMsg)
        fileMsg.add_header('Content-Disposition','attachment;filename='+self.sanitize(sendfilename))
        msg.attach(fileMsg)
        return msg

    def sendReport(self, file_name=None, file_content=None):
        mail_base = self.create_mime_multipart(self.me, self.recipients, self.getSubject())
        mail = self.set_body(mail_base, self.body)
        #encrypt_for(recipients, filename, encriptedfilename, gpgfolder)
        if file_content:
            self.attach_file(mail, file_name or self.file_name, file_content)
        self.send_mail(mail, self.me, self.recipients, self.mail_server)

    def sendError(self, info_error):
        mail_base = self.create_mime_multipart(self.me, self.recipients_error, self.getSubject("[ERROR]"))
        mail = self.set_body(mail_base, info_error)
        self.send_mail(mail, self.me, self.recipients_error, self.mail_server)


    def sendInfo(self, info_log):
        mail_base = self.create_mime_multipart(self.me, self.recipients_log, self.getSubject("[INFO]"))
        mail = self.set_body(mail_base, info_log)
        self.send_mail(mail, self.me, self.recipients_error, self.mail_server)

    def send_mail(self, msg, me, recipients, server):
        #enviar
        s = smtplib.SMTP(server)
        s.sendmail(me, recipients, msg.as_string())
        s.quit()

#    def send_text_mail(self, msg, me, recipients, server):
#        #enviar
#        s = smtplib.SMTP(server)
#        s.sendmail(me, recipients, msg)
#        s.quit()


#    def send_report(self, me, recipients, subject, body, server, file_name="report.txt", file_content=None):
#        mail_base = create_mime_multipart(me, recipients, subject)
#        mail = set_body(mail_base, body)
#        #encrypt_for(recipients, filename, encriptedfilename, gpgfolder)
#        if file_content:
#            attach_file(mail, file_name, file_content)
#        send_mail(mail, me, recipients, server)

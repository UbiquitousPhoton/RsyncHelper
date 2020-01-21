#!/usr/bin/env python3

#   MIT License
#
#   Copyright (c) 2019 Paul Elliott
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.

# RsyncHelper.py - a wrapper for rsync in python that would allow reporting via logfile
# and / or email of a regular sync job, most likely run from cron or systemd. Configuarion is
# via ini file.

import os
import argparse
import logging
import configparser
import smtplib
from email.mime.text import MIMEText
import socket
import sys
import subprocess
from subprocess import Popen, PIPE
from datetime import datetime
import shlex
from enum import Enum

class FileLogger:

    def __init__(self):
        self.logger = logging.getLogger("RsyncHelper")
        self.log_formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s",
                                               datefmt="%H:%M:%S")
        self.rotated_logfiles = []

    def RotateOldFiles(self, logfile, num_rotated):
        if logfile not in self.rotated_logfiles:
            if(os.path.isfile(logfile)):

                if os.path.isfile("{}.{}".format(logfile, num_rotated)):
                    os.remove("{}.{}".format(logfile, num_rotated))

                for file_ver in range(num_rotated, 0, -1):
                    if file_ver > 1:
                        target_file = "{}.{}".format(logfile, (file_ver - 1))
                    else:
                        target_file = logfile

                    if os.path.isfile(target_file):
                        os.replace(target_file, "{}.{}".format(logfile, file_ver))

                self.rotated_logfiles.append(logfile)

    def SetLogfile(self, logfile, num_rotated):

        if logfile != '':
            # There can be only one...
            if self.logger.hasHandlers():
                self.logger.removeHandler(self.log_handler)

            self.RotateOldFiles(logfile, num_rotated)

            self.log_handler = logging.FileHandler(logfile)

            self.logger.addHandler(self.log_handler)
            self.logger.setLevel(logging.INFO)
            self.log_handler.setFormatter(self.log_formatter)

    def Log(self, log_level, log_string):

        if self.logger.hasHandlers():
            self.logger.log(log_level, log_string)


class MailLogger:

    def __init__(self):
        self.initialised = False
        self.body = ""

    def Setup(self, server, from_email, to_email, subject):
        if self.initialised and self.body != "" and (server != self.server or from_email
                                                     != self.from_email or to_email
                                                     != self.to_email or subject
                                                     != self.subject):
            Send(self)

        self.server = server
        self.from_email = from_email
        self.to_email = to_email
        self.subject = subject
        self.initialised = True

    def AddToBody(self, body):

        if self.initialised == True:
            self.body = self.body + body + "\n"

    def Send(self):

        if self.initialised == True:
            email_msg = MIMEText(self.body)
            email_msg["Subject"] = self.subject
            email_msg["From"] = self.from_email
            email_msg["To"] = self.to_email

            # Send the message via our own SMTP server, but don't include the
            # envelope header.
            mail_server = smtplib.SMTP(self.server)
            mail_server.sendmail(self.from_email, self.to_email, email_msg.as_string())
            mail_server.quit()

            self.body = ""
            self.initialised = False


class SyncLogger:

    def __init__(self):

        self.file_logger = FileLogger()
        self.mail_logger = MailLogger()

    def SetLogfile(self, logfile, num_rotated):
        self.file_logger.SetLogfile(logfile, num_rotated)

    def SetupMail(self, server, from_email, to_email, subject):
        self.mail_logger.Setup(server, from_email, to_email, subject)

    def Log(self, log_level, message):
        self.mail_logger.AddToBody(message)
        self.file_logger.Log(log_level, message)

    def SendMail(self):
        self.mail_logger.Send()


class SyncMounter:

    class MountType(Enum):
        mount_none = 0
        mount_check = 1
        mount_try = 2


    def __init__(self):
        self.mount_type = SyncMounter.MountType.mount_none

    def Setup(self, sync_logger, sync_section, sync_section_name):

        if self.mount_type != SyncMounter.MountType.mount_none:
            Shutdown(self)

        self.mount_type = SyncMounter.MountType.mount_none

        if "try_mount" in sync_section:
            self.mount_point = sync_section.get("try_mount")
            self.mount_type = SyncMounter.MountType.mount_try

        elif "check_mount" in sync_section:
            self.mount_point = sync_section.get("check_mount")
            self.mount_type = SyncMounter.MountType.mount_check

        self.should_unmount = sync_section.getboolean("should_unmount", False)

        if self.mount_type != SyncMounter.MountType.mount_none:

            if not os.path.ismount(self.mount_point):

                if self.mount_type == SyncMounter.MountType.mount_check:
                    sync_logger.Log(logging.ERROR,
                                    "Checked mount {} not mounted, abandoning section {}".format(self.mount_point,
                                                                                                 sync_section_name))
                    return False

                else:
                    if not os.path.isdir(self.mount_point):
                        Do_Shell_Exec(sync_logger, "mkdir -p {}".format(self.mount_point))

                    Do_Shell_Exec(sync_logger, "mount {}".format(self.mount_point))

                    if not os.path.ismount(self.mount_point):

                        sync_logger.Log(logging.ERROR,
                                        "Attempt to mount {} failed, abandoning section {}".format(self.mount_point,
                                                                                                   sync_section_name))
                        self.mount_type = SyncMounter.MountType.mount_none
                        return False
                    else:
                        sync_logger.Log(logging.INFO,
                                        "Successfully mounted {}".format(self.mount_point))
            else:
                sync_logger.Log(logging.INFO,
                                "Checked mount {} is mounted".format(self.mount_point))

        return True

    def Shutdown(self, sync_logger, sync_section, sync_section_name):

        if self.mount_type == SyncMounter.MountType.mount_try and self.should_unmount:
            Do_Shell_Exec(sync_logger, "umount {}".format(self.mount_point))

            if not os.path.ismount(self.mount_point):

                sync_logger.Log(logging.INFO,
                                "Successfully unmounted {} for section {}".format(self.mount_point,
                                                                                  sync_section_name))
                return False
            else:
                sync_logger.Log(logging.ERROR,
                                "Failed to unmount {} for setion {}".format(self.mount_point,
                                                                            sync_section_name))

        self.mount_type = SyncMounter.MountType.mount_none


def Check_Elements(element_list, required_element_list, sync_logger, section_name):

    for element in required_element_list:
        if element not in element_list:
            error_msg = ("Invalid config : {} not found in sync section {}".format(element,
                                                                                   section_name))
            sync_logger.Log(logging.ERROR, error_msg)
            return False

    return True

def Do_Shell_Exec(sync_logger, exec_string):

    shell_process = Popen(shlex.split(exec_string), stdin=PIPE, stdout=PIPE, stderr=PIPE)

    (shell_stdout, shell_stderr) = shell_process.communicate()

    if shell_process.returncode != 0:
        sync_logger.Log(logging.INFO, "{} returned {}".format(exec_string,
                                                              shell_process.returncode))
        sync_logger.Log(logging.INFO, "stderr: {}".format(shell_stderr.decode("UTF-8")))
        return False

    else:
        sync_logger.Log(logging.INFO, "stdout: {}".format(shell_stdout.decode("UTF-8")))
        return True

def Setup_Logging_And_Mail(sync_logger, sync_section, sync_section_name):

    essential_mail_elements = ["mail_to", "mail_from", "mail_server"]
    mail_elements = essential_mail_elements.copy()
    mail_elements.extend(["mail_server_port", "mail_subject"])

    if 'logfile' in sync_section:
        sync_logger.SetLogfile(sync_section.get("logfile"), sync_section.get("num_keep_logs", 5))

    mail_found = False

    # if one of the mail elements is in the config, make sure all the required ones are.
    for element in mail_elements:
        if element in sync_section:
            mail_found = True
            break

    if mail_found == True:
        if Check_Elements(sync_section, essential_mail_elements, sync_logger, sync_section_name):
            server = sync_section.get("mail_server", "127.0.0.1")
            subject = sync_section.get("mail_subject",
                                       "Rsync Helper on {}".format(socket.gethostname()))

            sync_logger.SetupMail(server, sync_section.get("mail_from"),
                                  sync_section.get("mail_to"), subject)

            return True
        else:
            return False
    else:
        return True

def Do_Sync(sync_logger, sync_section, sync_section_name):

    essential_local_elements = ["target_dir", "source_dir"]
    essential_remote_elements = essential_local_elements.copy()
    essential_remote_elements.extend(["remote_user", "remote_host"])

    should_delete = sync_section.getboolean('delete', False)

    if should_delete:
        delete_string = "--delete"
    else:
        delete_string = ""

    sync_type = sync_section.get("sync_type", "local").lower()

    if sync_type == "local":

        if not Check_Elements(sync_section, essential_local_elements,
                              sync_logger,
                              sync_section_name):
            return False

        if not Do_Shell_Exec(sync_logger,
                             "rsync -avc {} {} {}".format(delete_string,
                                                          sync_section.get('source_dir'),
                                                          sync_section.get('target_dir'))):
            return False

    elif sync_type == "remote":

        if not Check_Elements(sync_section, essential_remote_elements,
                              sync_logger,
                              sync_section_name):
            return False

        if not Do_Shell_Exec(sync_logger,
                             "rsync -avc {} --rsh=ssh {}@{}::{} {}".format(delete_string,
                                                                           sync_section.get('remote_user'),
                                                                           sync_section.get('remote_host'),
                                                                           sync_section.get('source_dir'),
                                                                           sync_section.get('target_dir'))):
            return False

    else:
        error_msg = ("Invalid sync type : {} for sync section {}".format(sync_type,
                                                                         section_name))
        sync_logger.Log(logging.ERROR, error_msg)
        return False

    return True


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Rsync wrapper for scheduled jobs')
    parser.add_argument("config_file", help="Sync Config File", type = argparse.FileType('r'))
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read_file(args.config_file)

    sync_logger = SyncLogger()
    sync_mounter = SyncMounter()

    for sync_section_name in config.sections():

        sync_section = config[sync_section_name]
        should_continue = True

        if not Setup_Logging_And_Mail(sync_logger, sync_section, sync_section_name):
            continue

        start_time = datetime.now()
        sync_logger.Log(logging.INFO,
                        "Sync section {} begins {}".format(sync_section_name,
                                                           start_time.strftime("%d/%m/%Y %H:%M")))

        if not sync_mounter.Setup(sync_logger, sync_section, sync_section_name):
            continue

        if not Do_Sync(sync_logger, sync_section, sync_section_name):
            continue

        end_time = datetime.now()
        time_taken = end_time - start_time;
        hours_taken, taken_remainder = divmod(time_taken.total_seconds(), 3600)
        minutes_taken, seconds_taken = divmod(taken_remainder, 60)

        if hours_taken > 0:
            taken_string = "{} hours, {} min".format(hours_taken, minutes_taken)
        else:
            taken_string = "{} min {} secs".format(minutes_taken, seconds_taken)

        sync_logger.Log(logging.INFO,
                        "Sync section {} ends {} (Took {})".format(sync_section_name,
                                                                   end_time.strftime("%d/%m/%Y %H:%M"),
                                                                   taken_string))

        if "post_sync" in sync_section:
            sync_logger.Log(logging.INFO,
                            "Executing post sync action for {}".format(sync_section_name))
            Do_Shell_Exec(sync_logger, sync_section.get('post_sync'))

    sync_mounter.Shutdown(sync_logger, sync_section, sync_section_name)
    sync_logger.SendMail()


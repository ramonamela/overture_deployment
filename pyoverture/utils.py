from os import chmod
from Crypto.PublicKey import RSA
from fabric import Connection
from io import StringIO
import sys
import paramiko
from time import sleep

def generate_rsa_keys(tmp_public_key, tmp_private_key):
    key = RSA.generate(2048)
    with open(tmp_private_key, 'wb') as content_file:
        chmod(tmp_private_key, 0o0600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(tmp_public_key, 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))
    return pubkey.exportKey('OpenSSH').decode("utf-8")

def run_command_ssh_gateway(conn, username, ip, command):
    constructed_command = "eval $'ssh -oStrictHostKeyChecking=no " + username + "@" + ip + \
                          " <<\\'EOF\\'\n" + command + "\nEOF'"

    max_connection_refused_retries = 10
    connection_refused_errors = 0
    keep_trying = True

    while keep_trying:
        print(".", end="")
        sys.stdout.flush()

        try:
            stdout = StringIO()
            stderr = StringIO()
            conn.run(constructed_command, out_stream=stdout, err_stream=stderr)
            print("")
            return stdout.getvalue(), stderr.getvalue()
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            if not "Unable to connect to port 22" in str(e):
                raise (e)
        except Exception as e:
            stderr.seek(0)
            stderr_string = stderr.getvalue()
            if not "No route to host" in stderr_string:
                if "Connection refused" in stderr_string:
                    if connection_refused_errors < max_connection_refused_retries:
                        connection_refused_errors += 1
                    else:
                        print(stdout.getvalue())
                        print(stderr.getvalue())
                        raise e
                else:
                    print(stdout.getvalue())
                    print(stderr.getvalue())
                    raise e
        sleep(1)
    print("")

def mount_nfs(public_ip_login_node, private_ip_node, nfs_ip, nfs_mount_point, nfs_origin, local_private,
              username="user"):
    print("Waiting until nfs is mounted", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                       forward_agent=True)

    auto_direct_line = "\"" + nfs_mount_point + \
                     "\t-rw,noatime,rsize=1048576,wsize=1048576,nolock,intr,tcp,actimeo=1800\t" + nfs_ip + ":" + \
                     nfs_origin + "\""
    command_to_run = "sudo mkdir -p /etc/auto.master.d\n" \
                     "echo \"/-\t/etc/auto.direct\" | sudo tee -a /etc/auto.master.d/direct.autofs > /dev/null\n" \
                     "echo " + auto_direct_line + " | sudo tee -a /etc/auto.direct > /dev/null\n" \
                     "sudo /etc/init.d/autofs restart"
    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()
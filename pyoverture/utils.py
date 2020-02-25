from os import chmod
from Crypto.PublicKey import RSA
from fabric import Connection
from io import StringIO
import sys
import paramiko
from time import sleep
import invoke


def generate_rsa_keys(tmp_public_key, tmp_private_key):
    key = RSA.generate(2048)
    with open(tmp_private_key, 'wb') as content_file:
        chmod(tmp_private_key, 0o0600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(tmp_public_key, 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))
    return pubkey.exportKey('OpenSSH').decode("utf-8")


def run_command_ssh_gateway(conn, username, ip, command, background=False):
    constructed_command = "eval $'ssh -oStrictHostKeyChecking=no " + username + "@" + ip + \
                          " <<\\'EOF\\'\n" + command

    if background:
        constructed_command += "\nEOF' &"
    else:
        constructed_command += "\nEOF'"

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
            conn.close()
            return stdout.getvalue(), stderr.getvalue()
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            if "Unable to connect to port 22" not in str(e):
                raise e
        except invoke.exceptions.UnexpectedExit:
            stderr.seek(0)
            stderr_string = stderr.getvalue()
            if "No route to host" not in stderr_string:
                if "Connection refused" in stderr_string:
                    if connection_refused_errors < max_connection_refused_retries:
                        connection_refused_errors += 1
                    else:
                        print(stdout.getvalue())
                        print(stderr.getvalue())
                        raise Exception(stderr.getvalue())
                else:
                    print(stdout.getvalue())
                    print(stderr.getvalue())
                    raise Exception(stderr.getvalue())
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


def install_nfs_dependencies(public_ip_login_node, private_ip_node, local_private, username="user"):
    print("Waiting until nfs dependencies are installed", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)

    command_to_run = "sudo apt-get -y --no-install-recommends install nfs-common autofs"
    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()


def install_docker_dependencies(public_ip_login_node, private_ip_node, local_private, username="user"):
    print("Waiting until docker dependencies are installed", end="")
    command_to_run = "sudo apt-get remove -y docker docker-engine docker.io containerd runc\n" \
                     "sudo apt-get update\n" \
                     "sudo apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl " \
                     "gnupg-agent software-properties-common\n" \
                     "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -\n" \
                     "sudo add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu " \
                     "$(lsb_release -cs) stable\"\n" \
                     "sudo apt-get update\n" \
                     "sudo apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io\n" \
                     "sudo curl -L \"https://github.com/docker/compose/releases/download/1.25.0/docker-compose-" \
                     "$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose\n" \
                     "sudo chmod +x /usr/local/bin/docker-compose\n" \
                     "sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose\n" \
                     "service docker status\n" \
                     "sudo usermod -aG docker ${USER}\n"
    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)
    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()


def apt_get_update(public_ip_login_node, private_ip_node, local_private, username="user"):
    print("Waiting until the machine is reachable by ssh and running secure apt get update", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)

    command_to_run = "pid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | " \
                     "awk \\'{ print $4 }\\' | xargs -i echo {});while [[ ! -z \"${pid}\" && -e /proc/${pid} ]]; " \
                     "do sleep 0.1; done;sudo apt-get update;"

    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()

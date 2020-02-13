#!/usr/bin/env python3
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver
import pyone
import sys
from enum import Enum
from os import chmod
from Crypto.PublicKey import RSA
from time import sleep
from fabric import Connection
import paramiko
from collections import OrderedDict
from io import StringIO
from pyoverture.starlifetemplate import NIC
from pyoverture.starlifetemplate import Template
from pyoverture.starlifetemplate import VirtualImages
from pyoverture.starlifetemplate import Description
from os import environ

def create_template(one, template_name, username, password, virtual_image=VirtualImages.UBUNTU1804KVM, cpu=2,
                    memory=None, cluster=Description, overwrite=False, nics=[], hostname=None, ip_forward=None,
                    automount_nfs=None, gateway_interface=None, graphics=False, ssh_public_key=None, disk_size=None):
    if not isinstance(virtual_image, VirtualImages):
        raise Exception("Unknown base image")

    ## Check if a template already exists with this name
    vm_template = one.templatepool.info(-1, -1, -1).VMTEMPLATE
    for elem in vm_template:
        if elem.get_NAME() == template_name:
            if overwrite:
                print("Erasing existant template with name \"%s\"" % (template_name), file=sys.stderr)
                ret = one.template.delete(elem.get_ID())
            else:
                raise Exception("A template with name \"%s\" already exists" % (template_name))

    current_machine = Template(one, template_name, virtual_image, username, password, cpu, memory, cluster,
                               disk_size=disk_size, hostname=hostname, ip_forward=ip_forward,
                               automount_nfs=automount_nfs, ssh_public_key=ssh_public_key, additional_users=[],
                               gateway_interface=gateway_interface, automatic_update=False, graphics=graphics,
                               nics=nics)

    vm_templ = current_machine.get_full_template()

    print(vm_templ)

    ret = one.template.allocate(vm_templ)
    print("Created template with id %s" % (ret), file=sys.stderr)
    return ret


def wait_until_vm_running(one, vm_id, public_ip=None, private_key=None, user=None):
    print("Waiting until vm with id %d and name %s is running"
          % (vm_id, one.vmpool.info(-1, vm_id, vm_id, -1).VM[0].NAME), end="")
    ## ACTIVE and RUNNING
    while not (one.vm.info(vm_id).STATE == 3 and one.vm.info(vm_id).LCM_STATE == 3):
        print(".", end="")
        sys.stdout.flush()
        sleep(1)
    print("")

    print("Waiting until vm with id %d and name %s has ssh reachable"
          % (vm_id, one.vmpool.info(-1, vm_id, vm_id, -1).VM[0].NAME), end="")
    if not public_ip is None:
        keep_trying = True
        connection_args = {}
        if not private_key is None:
            connection_args["connect_kwargs"] = {"key_filename": private_key}
        if not user is None:
            connection_args["user"] = user
        curr_conn = Connection(public_ip, **connection_args)
        while keep_trying:
            print(".", end="")
            sys.stdout.flush()
            try:
                curr_conn.open()
                curr_conn.close()
                keep_trying = False
            except paramiko.ssh_exception.NoValidConnectionsError as e:
                if not "Unable to connect to port 22" in str(e):
                    raise (e)
            sleep(1)
        print("")


def get_private_ip(one, instance_id):
    vm_list = one.vmpool.info(-1, instance_id, instance_id, -1)
    # print(vm_list.VM[0].TEMPLATE["NIC"])
    nic_list = vm_list.VM[0].TEMPLATE["NIC"]
    if (isinstance(nic_list, OrderedDict)):
        if nic_list["IP"].startswith("10."):
            print("")
            print("Unique IP returned:", nic_list["IP"])
            return nic_list["IP"]
        return None
    for nic in vm_list.VM[0].TEMPLATE["NIC"]:
        if nic["IP"].startswith("10."):
            print("")
            print("Several IP returned:", nic["IP"])
            return nic["IP"]
    return None


def instantiate_vm(one, base_template_id, base_instance_name, reset_base_image=False):
    reset_base_image = True
    try:
        new_vm_id = one.template.instantiate(base_template_id, base_instance_name)
        return new_vm_id
    except Exception as e:
        if "Cannot get IP/MAC" in e.args[0]:
            vm_list = one.vmpool.info(-1, -1, -1, -1)
            for vm in vm_list.VM:
                if vm.NAME == base_instance_name:
                    for nic in vm.TEMPLATE["NIC"]:
                        if nic["IP"] == "84.88.186.194":
                            if reset_base_image:
                                print(
                                    "The supplied IP is already in use by a running VM named %s. We will try to erase it "
                                    "and try again." % (base_instance_name))
                                one.vm.action("terminate-hard", vm.get_ID())
                                print("Virtual Machine with id %s and name %s still not in state DONE" % (
                                    vm.get_ID(), vm.NAME), end="")
                                while not (one.vm.info(vm.get_ID()).STATE == 6):
                                    print(".", end="")
                                    sys.stdout.flush()
                                    sleep(1)
                                print("")
                                new_vm_id = one.template.instantiate(base_template_id, base_instance_name)
                                return new_vm_id
                            else:
                                print(
                                    "The supplied IP is already in use by a running VM named %s. Set reset base image to "
                                    "True if you want to try to erase it and try again." % (base_instance_name))
                                return None
            print(
                "The supplied IP is already in use by a running VM named %s. Since this is not the same name supplied,"
                "it cannot be assumed that it is the same machine. If you want to erase it, erase it by hand."
                % (base_instance_name))
        else:
            raise (e)

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

def apt_get_update(public_ip_login_node, private_ip_node, local_private, username="user"):

    print("Waiting until the machine is reachable by ssh and running secure apt get update", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                       forward_agent=True)
    """
    command_to_run = "'pid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | awk \'{ print $4 }\' | xargs -i " \
                     "echo {});" \
                     "while [ -e /proc/${pid} ]; do sleep 0.1; done; " \
                     "sudo apt-get update; sudo apt-get -y --no-install-recommends install nfs-common autofs'"
    constructed_command = "ssh -oStrictHostKeyChecking=no " + username + "@" + private_ip_node + " " + \
                          command_to_run
    """
    command_to_run = "pid=$(ps -elfa | grep apt | grep lock_is_held | grep -v grep | " \
                     "awk \\'{ print $4 }\\' | xargs -i echo {});while [[ ! -z \"${pid}\" && -e /proc/${pid} ]]; " \
                     "do sleep 0.1; done;sudo apt-get update;"
    #constructed_command = "eval $'ssh -oStrictHostKeyChecking=no " + username + "@" + private_ip_node + \
    #                      " <<\\'EOF\\'\n" + command_to_run + "\nEOF'"

    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()

def install_nfs_dependencies(public_ip_login_node, private_ip_node, local_private, username="user"):
    print("Waiting until nfs dependencies are installed", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                       forward_agent=True)

    command_to_run = "sudo apt-get -y --no-install-recommends install nfs-common autofs"
    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()

def install_postgres_dependencies(public_ip_login_node, private_ip_node, local_private, username="user"):
    print("Waiting until the dependencies are installed", end="")

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                       forward_agent=True)

    command_to_run = "sudo apt-get -y --no-install-recommends install nfs-common autofs"
    run_command_ssh_gateway(conn, username, private_ip_node, command_to_run)
    conn.close()

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

def generate_rsa_keys(tmp_public_key, tmp_private_key):
    key = RSA.generate(2048)
    with open(tmp_private_key, 'wb') as content_file:
        chmod(tmp_private_key, 0o0600)
        content_file.write(key.exportKey('PEM'))
    pubkey = key.publickey()
    with open(tmp_public_key, 'wb') as content_file:
        content_file.write(pubkey.exportKey('OpenSSH'))
    return pubkey.exportKey('OpenSSH').decode("utf-8")

def create_machines(one, base_user, base_pass, public_ip_login_node, public_network, private_network,
                    tmp_public_key, tmp_private_key, remote_private_key, nfs_ip, nfs_dest, nfs_origin):
    ## Could not manage to import a new image into the datastore in an automated way
    #  By now, it must be done manually with the graphical interface
    #  Apps -> Look for the desired distribution (in this case, "ubuntu" in the searcher and "Ubuntu Minimal 18.04 - KVM
    #  -> Click into the cloud icon -> Set up a name, select the local datastore (BSC-EUCC Images) -> Download
    #  In case this must change, add an other value in the class VirtualImages

    ## First of all, we need to create a temporal ssh key to perform the connections to the base image

    create_master = False

    if create_master:
        public_key_object = generate_rsa_keys(tmp_public_key, tmp_private_key)
    else:
        with open(tmp_public_key, 'rb') as public_key_file:
            public_key_object = public_key_file.read().decode("utf-8")

    ## The most important thing in this step is to realize that the public IP must be available
    #  Base template to create the base image
    #  The gateway_interface will be, in general, the position of the public IP in the 'nics' array
    base_template_master = create_template(one, "overture_base_template_master", base_user, base_pass,
                                           virtual_image=VirtualImages.UBUNTU1804KVM, overwrite=True,
                                           nics=[NIC(one, public_network, network_ip=public_ip_login_node),
                                                 NIC(one, private_network)],
                                           graphics=True, gateway_interface=0, ip_forward=("eth0", "eth1"),
                                           ssh_public_key=public_key_object)

    base_template_slaves = create_template(one, "overture_base_template_slaves", base_user, base_pass,
                                           virtual_image=VirtualImages.UBUNTU1804KVM, overwrite=True,
                                           nics=[NIC(one, private_network)],
                                           graphics=True, gateway_interface=0,
                                           ssh_public_key=public_key_object, disk_size=16384)
                                            #automount_nfs=(nfs_ip, nfs_origin, nfs_dest),

    if create_master:
        base_master_vm_id = instantiate_vm(one, base_template_master, "overture_base_vm_master", reset_base_image=True)

        wait_until_vm_running(one, base_master_vm_id, public_ip=public_ip_login_node, private_key=tmp_private_key,
                              user="user")

        conn_to_login = Connection(host=public_ip_login_node, user="user",
                                   connect_kwargs={"key_filename": tmp_private_key})
        conn_to_login.put(tmp_private_key, remote_private_key)

        private_ip = get_private_ip(one, base_master_vm_id)
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
    ## If we shutdown the master node, the public IP stop being available
    # base_master_vm_id = one.vm.action("poweroff", one.vmpool.info(-1, base_master_vm_id, base_master_vm_id, -1).VM[0].ID)

    try:
        base_song_vm_id = instantiate_vm(one, base_template_slaves, "overture_base_vm_song", reset_base_image=True)
        wait_until_vm_running(one, base_song_vm_id)
        private_ip = get_private_ip(one, base_song_vm_id)
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key, username="user")
        #base_song_vm_id = one.vm.action("poweroff", one.vmpool.info(-1, base_song_vm_id, base_song_vm_id, -1).VM[0].ID)
    except Exception as e:
        print(e)
        one.vm.action("terminate", one.vmpool.info(-1, base_song_vm_id, base_song_vm_id, -1).VM[0].ID)
        raise e

    try:
        base_score_vm_id = instantiate_vm(one, base_template_slaves, "overture_base_vm_score", reset_base_image=True)
        wait_until_vm_running(one, base_score_vm_id)
        private_ip = get_private_ip(one, base_score_vm_id)
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key, username="user")
        #base_score_vm_id = one.vm.action("poweroff",
        #                                 one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
    except Exception as e:
        print(e)
        one.vm.action("terminate", one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
        raise e

    try:
        base_postgres_song_vm_id = instantiate_vm(one, base_template_slaves, "overture_base_vm_postgres_song",
                                                  reset_base_image=True)
        wait_until_vm_running(one, base_postgres_song_vm_id)
        private_ip = get_private_ip(one, base_postgres_song_vm_id)
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key, username="user")
        #base_score_vm_id = one.vm.action("poweroff",
        #                                 one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
    except Exception as e:
        print(e)
        one.vm.action("terminate", one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
        raise e

    try:
        base_all_in_one_vm_id = instantiate_vm(one, base_template_slaves, "overture_base_vm_all_in_one",
                                                  reset_base_image=True)
        wait_until_vm_running(one, base_all_in_one_vm_id)
        private_ip = get_private_ip(one, base_all_in_one_vm_id)
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key, username="user")
        #base_score_vm_id = one.vm.action("poweroff",
        #                                 one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
    except Exception as e:
        print(e)
        one.vm.action("terminate", one.vmpool.info(-1, base_score_vm_id, base_score_vm_id, -1).VM[0].ID)
        raise e

    return base_song_vm_id, base_score_vm_id, base_postgres_song_vm_id, base_all_in_one_vm_id

def deploy_score(one, public_ip_login_node, score_vm_id):
    pass

def deploy_song(one, public_ip_login_node, song_vm_id, postgres_song_vm_id):
    deploy_script="VERSION=4.0.0" + \
                  "curl " + \
                  "\"https://artifacts.oicr.on.ca/artifactory/dcc-release/bio/overture/song-server/$VERSION/song-server-$VERSION-dist.tar.gz\" " + \
                  "-Ls -o song-server-$VERSION-dist.tar.gz" \
                  "tar zxvf song-server-$VERSION-dist.tar.gz"

def deploy_full_test_stack(one, public_ip_login_node, base_all_in_one_vm_id, local_private, username):
    ## https://song-docs.readthedocs.io/en/develop/docker.html
    private_ip = get_private_ip(one, base_all_in_one_vm_id)
    playground_version = "1.0.0"
    download_song = "export PLAY_VERSION=" + playground_version + "\n" \
                    "rm -rf ${PLAY_VERSION}\n" \
                    "git clone --branch $PLAY_VERSION https://github.com/overture-stack/genomic-data-playground.git $PLAY_VERSION\n"
                    #"cd ${PLAY_VERSION}\n"
                    #"sed -i \\'1 s@3.7@3.5@g\\' docker-compose.yml\n"
    install_docker = "sudo apt-get remove -y docker docker-engine docker.io containerd runc\n" \
                     "sudo apt-get update\n" \
                     "sudo apt-get install -y --no-install-recommends apt-transport-https ca-certificates curl " \
                     "gnupg-agent software-properties-common\n" \
                     "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -\n" \
                     "sudo add-apt-repository \"deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable\"\n" \
                     "sudo apt-get update\n" \
                     "sudo apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io\n" \
                     "sudo curl -L \"https://github.com/docker/compose/releases/download/1.25.0/docker-compose-$(uname -s)-$(uname -m)\" -o /usr/local/bin/docker-compose\n" \
                     "sudo chmod +x /usr/local/bin/docker-compose\n" \
                     "sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose\n" \
                     "service docker status\n" \
                     "sudo usermod -aG docker ${USER}\n"
    install_mandatory_dependencies = "sudo apt-get install -y --no-install-recommends make\n"
    run_docker_compose = "export PLAY_VERSION=" + playground_version + "\n" \
                         "cd ${PLAY_VERSION}\n" \
                         "make clean\n" \
                         "make start-services\n"
                         #"export DOCKERFILE_NAME=/home/" + username + "/${PLAY_VERSION}/Dockerfile\n" \
                         #"docker-compose build\n" \
                         #"docker-compose up -d\n" \
                         #"docker ps\n"
    install_useful_dependencies = "sudo apt-get install -y --no-install-recommends jq\n"

    first_deploy_script = download_song + install_docker + install_useful_dependencies
    second_deploy_script = install_mandatory_dependencies + run_docker_compose# + check_server_status

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)

    print("Download song and install docker and all dependencies")
    out, err = run_command_ssh_gateway(conn, username, private_ip, first_deploy_script)
    print(out)
    print(err)
    print("Docker compose")
    out, err = run_command_ssh_gateway(conn, username, private_ip, second_deploy_script)
    print(out)
    print(err)

def main(server_address, user, password, reset_base_image=False):
    public_ip_login_node = "84.88.186.194"
    nfs_ip = "10.32.3.253"
    public_network = "BSC-Public-122"
    private_network = "BSC-EUCC-Cloud-1003"
    nfs_origin = "/slgpfs/cloud/BSC/EUCC"
    nfs_dest = "/mnt/nfs"
    base_user = "user"
    base_pass = "user"
    tmp_rsa_folder = "/home/ramela/tmp"
    tmp_private_key = tmp_rsa_folder + "/private.key"
    tmp_public_key = tmp_rsa_folder + "/public.key"
    ## https://github.com/fabric/fabric/issues/1492
    ## Due to a fabric limitation, we MUST store the private key with this name
    remote_private_key = "/home/" + base_user + "/.ssh/id_rsa"

    one = pyone.OneServer(server_address, session=user + ":" + password)

    create_mach = True
    if create_mach:
        song_vm_id, score_vm_id, postgres_song_vm_id, base_all_in_one_vm_id = create_machines(one, base_user, base_pass,
                                                                                              public_ip_login_node,
                                                                                              public_network,
                                                                                              private_network,
                                                                                              tmp_public_key,
                                                                                              tmp_private_key,
                                                                                              remote_private_key,
                                                                                              nfs_ip, nfs_dest,
                                                                                              nfs_origin)
    else:
        base_all_in_one_vm_id = 1758

    #song_vm_id, score_vm_id, postgres_song_vm_id = 1711, 1712

    #deploy_score(one, public_ip_login_node, score_vm_id)

    #deploy_song(one, public_ip_login_node, song_vm_id, postgres_song_vm_id)
    #base_all_in_one_vm_id = 1723
    #base_all_in_one_vm_id = 1734
    deploy_full_test_stack(one, public_ip_login_node, base_all_in_one_vm_id, tmp_private_key, base_user)

    # wait_until_vm_running(one, base_master_vm_id)
    # print(result)


if __name__ == "__main__":
    username = environ["SL_USER"]
    password = environ["SL_PASS"]
    print(username)
    print(password)
    main("http://slcloud1.bsc.es:2633/RPC2", "ramela", "ramela")

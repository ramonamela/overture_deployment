#!/usr/bin/env python3
# from libcloud.compute.types import Provider
# from libcloud.compute.providers import get_driver
import sys
from time import sleep
from fabric import Connection
import paramiko
from collections import OrderedDict
from pyoverture.starlife import NIC
from pyoverture.starlife import Template
from pyoverture.starlife import VirtualImages
from pyoverture.starlife import Description
from pyoverture.starlife import CloudSession
from pyoverture.starlife import VirtualMachine
from pyoverture.utils import generate_rsa_keys
from pyoverture.utils import run_command_ssh_gateway
from pyoverture.utils import mount_nfs
from pyoverture.utils import install_nfs_dependencies
from pyoverture.utils import apt_get_update

from os import environ


def create_template(cloud_session, template_name, template_username, template_password,
                    virtual_image=VirtualImages.UBUNTU1804KVM, cpu=2, memory=None, cluster=Description, overwrite=False,
                    nics=(), hostname=None, ip_forward=None, automount_nfs=None, gateway_interface=None, graphics=False,
                    ssh_public_key=None, disk_size=None):
    if not isinstance(virtual_image, VirtualImages):
        raise Exception("Unknown base image")

    current_template = Template(cloud_session, template_name, virtual_image, template_username, template_password, cpu,
                                memory, cluster, disk_size=disk_size, hostname=hostname, ip_forward=ip_forward,
                                automount_nfs=automount_nfs, ssh_public_key=ssh_public_key, additional_users=[],
                                gateway_interface=gateway_interface, automatic_update=False, graphics=graphics,
                                nics=nics)

    current_template.allocate_template(overwrite=overwrite)
    print("Created template with id %s" % current_template.get_id(), file=sys.stderr)
    return current_template


def create_machines(cloud_session, base_user, base_pass, public_ip_login_node, public_network, private_network,
                    tmp_public_key, tmp_private_key, remote_private_key, nfs_ip, nfs_dest, nfs_origin):
    # Could not manage to import a new image into the datastore in an automated way
    #  By now, it must be done manually with the graphical interface
    #  Apps -> Look for the desired distribution (in this case, "ubuntu" in the searcher and "Ubuntu Minimal 18.04 - KVM
    #  -> Click into the cloud icon -> Set up a name, select the local datastore (BSC-EUCC Images) -> Download
    #  In case this must change, add an other value in the class VirtualImages

    # First of all, we need to create a temporal ssh key to perform the connections to the base image
    create_master = True

    if create_master:
        public_key_object = generate_rsa_keys(tmp_public_key, tmp_private_key)
    else:
        with open(tmp_public_key, 'rb') as public_key_file:
            public_key_object = public_key_file.read().decode("utf-8")

    # The most important thing in this step is to realize that the public IP must be available
    #  Base template to create the base image
    #  The gateway_interface will be, in general, the position of the public IP in the 'nics' array
    base_template_master = create_template(cloud_session, "overture_base_template_master", base_user, base_pass,
                                           virtual_image=VirtualImages.UBUNTU1804KVM, overwrite=True,
                                           nics=[NIC(cloud_session, public_network, network_ip=public_ip_login_node),
                                                 NIC(cloud_session, private_network)],
                                           graphics=True, gateway_interface=0, ip_forward=("eth0", "eth1"),
                                           ssh_public_key=public_key_object)

    base_template_slaves = create_template(cloud_session, "overture_base_template_slaves", base_user, base_pass,
                                           virtual_image=VirtualImages.UBUNTU1804KVM, overwrite=True,
                                           nics=[NIC(cloud_session, private_network)],
                                           graphics=True, gateway_interface=0,
                                           ssh_public_key=public_key_object, disk_size=16384)
    # automount_nfs=(nfs_ip, nfs_origin, nfs_dest),
    # one = cloud_session.one
    if create_master:
        base_master_vm = VirtualMachine(base_template_master, "overture_base_vm_master", public_ip=public_ip_login_node,
                                        base_user=base_user)
        base_master_vm.instantiate(cloud_session=cloud_session, reset_image=True)
        base_master_vm.set_vm_conn_private_key(tmp_private_key)
        base_master_vm.wait_until_running()
        base_master_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        private_ip = base_master_vm.get_private_ip()
        apt_get_update(public_ip_login_node, private_ip, tmp_private_key)
        # NFS dependencies are not needed in the master since it should have not have the node mounted
        # install_nfs_dependencies(public_ip_login_node, private_ip, tmp_private_key)
    # If we shutdown the master node, the public IP stop being available
    # base_master_vm_id = one.vm.action("poweroff", one.vmpool.info(-1, base_master_vm_id,
    # base_master_vm_id, -1).VM[0].ID)

    base_song_vm = VirtualMachine(base_template_slaves, "overture_base_vm_song", public_ip=public_ip_login_node,
                                  base_user=base_user)
    try:
        base_song_vm.instantiate(cloud_session=cloud_session)
        base_song_vm.set_vm_conn_private_key(tmp_private_key)
        base_song_vm.wait_until_running()
        base_song_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        base_song_private_ip = base_song_vm.get_private_ip()
        apt_get_update(public_ip_login_node, base_song_private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, base_song_private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, base_song_private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key,
                  username="user")
    except Exception as e:
        print(e)
        base_song_vm.terminate()
        raise e

    base_score_vm = VirtualMachine(base_template_slaves, "overture_base_vm_score", public_ip=public_ip_login_node,
                                   base_user=base_user)
    try:
        base_score_vm.instantiate(cloud_session=cloud_session)
        base_score_vm.set_vm_conn_private_key(tmp_private_key)
        base_score_vm.wait_until_running()
        base_score_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        base_score_private_ip = base_score_vm.get_private_ip()
        apt_get_update(public_ip_login_node, base_score_private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, base_score_private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, base_score_private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key,
                  username="user")
    except Exception as e:
        print(e)
        base_score_vm.terminate()
        raise e

    base_postgres_song_vm = VirtualMachine(base_template_slaves, "overture_base_vm_postgres_song",
                                           public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_postgres_song_vm.instantiate(cloud_session=cloud_session)
        base_postgres_song_vm.set_vm_conn_private_key(tmp_private_key)
        base_postgres_song_vm.wait_until_running()
        base_postgres_song_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        base_postgres_private_ip = base_postgres_song_vm.get_private_ip()
        apt_get_update(public_ip_login_node, base_postgres_private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, base_postgres_private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, base_postgres_private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key,
                  username="user")
    except Exception as e:
        print(e)
        base_postgres_song_vm.terminate()
        raise e

    base_all_in_one_vm = VirtualMachine(base_template_slaves, "overture_base_vm_all_in_one",
                                        public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_all_in_one_vm.instantiate(cloud_session=cloud_session)
        base_all_in_one_vm.set_vm_conn_private_key(tmp_private_key)
        base_all_in_one_vm.wait_until_running()
        base_all_in_one_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        base_all_in_one_private_ip = base_postgres_song_vm.get_private_ip()
        apt_get_update(public_ip_login_node, base_all_in_one_private_ip, tmp_private_key)
        install_nfs_dependencies(public_ip_login_node, base_all_in_one_private_ip, tmp_private_key)
        mount_nfs(public_ip_login_node, base_all_in_one_private_ip, nfs_ip, nfs_dest, nfs_origin, tmp_private_key,
                  username="user")
    except Exception as e:
        print(e)
        base_all_in_one_vm.terminate()
        raise e

    return base_song_vm, base_score_vm, base_postgres_song_vm, base_all_in_one_vm


def deploy_full_test_stack(public_ip_login_node, base_all_in_one_vm, local_private, base_user):
    # https://song-docs.readthedocs.io/en/develop/docker.html
    private_ip = base_all_in_one_vm.get_private_ip()
    playground_version = "1.0.0"
    download_song = "export PLAY_VERSION=" + playground_version + "\n" \
                    "rm -rf ${PLAY_VERSION}\n" \
                    "git clone --branch $PLAY_VERSION https://github.com/overture-stack/genomic-data-playground.git " \
                                                                  "$PLAY_VERSION\n"
    # "cd ${PLAY_VERSION}\n"
    # "sed -i \\'1 s@3.7@3.5@g\\' docker-compose.yml\n"
    install_docker = "sudo apt-get remove -y docker docker-engine docker.io containerd runc\n" \
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
    install_mandatory_dependencies = "sudo apt-get install -y --no-install-recommends make\n"
    run_docker_compose = "export PLAY_VERSION=" + playground_version + "\n" \
                                                                       "cd ${PLAY_VERSION}\n" \
                                                                       "make clean\n" \
                                                                       "make start-services\n"
    # "export DOCKERFILE_NAME=/home/" + username + "/${PLAY_VERSION}/Dockerfile\n" \
    # "docker-compose build\n" \
    # "docker-compose up -d\n" \
    # "docker ps\n"
    install_useful_dependencies = "sudo apt-get install -y --no-install-recommends jq\n"

    first_deploy_script = download_song + install_docker + install_useful_dependencies
    second_deploy_script = install_mandatory_dependencies + run_docker_compose  # + check_server_status

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)

    print("Download song and install docker and all dependencies")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, first_deploy_script)
    print(out)
    print(err)
    print("Docker compose")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, second_deploy_script)
    print(out)
    print(err)


def main(server_address, cloud_user, cloud_password, reset_base_image=False):
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

    cloud_session = CloudSession(server_address, cloud_user, cloud_password)

    create_mach = True
    if create_mach:
        song_vm, score_vm, postgres_song_vm, base_all_in_one_vm = create_machines(cloud_session, base_user,
                                                                                  base_pass,
                                                                                  public_ip_login_node,
                                                                                  public_network,
                                                                                  private_network,
                                                                                  tmp_public_key,
                                                                                  tmp_private_key,
                                                                                  remote_private_key,
                                                                                  nfs_ip, nfs_dest,
                                                                                  nfs_origin)
    else:
        # Find a way to do this correctly 
        base_all_in_one_vm_id = 1758

    # song_vm_id, score_vm_id, postgres_song_vm_id = 1711, 1712

    # deploy_score(one, public_ip_login_node, score_vm_id)

    # deploy_song(one, public_ip_login_node, song_vm_id, postgres_song_vm_id)
    # base_all_in_one_vm_id = 1723
    # base_all_in_one_vm_id = 1734
    deploy_full_test_stack(cloud_session, public_ip_login_node, base_all_in_one_vm, tmp_private_key, base_user)


if __name__ == "__main__":
    username = environ["SL_USER"]
    password = environ["SL_PASS"]
    main("http://slcloud1.bsc.es:2633/RPC2", username, password)

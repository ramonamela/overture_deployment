#!/usr/bin/env python3
# from libcloud.compute.types import Provider
# from libcloud.compute.providers import get_driver
import sys
from os import environ
from pathlib import Path
# from time import sleep
# from fabric import Connection
# import paramiko
# from collections import OrderedDict
from pyoverture.starlife import NIC
from pyoverture.starlife import Template
from pyoverture.starlife import VirtualImages
from pyoverture.starlife import Description
from pyoverture.starlife import CloudSession
from pyoverture.starlife import VirtualMachine
from pyoverture.utils import generate_rsa_keys
from pyoverture.utils import mount_nfs
from pyoverture.utils import install_nfs_dependencies
from pyoverture.utils import apt_get_update
from pyoverture.utils import install_docker_dependencies
# from pyoverture.deployutils import deploy_full_test_stack
from pyoverture.deployutils import deploy_postgres
from pyoverture.deployutils import deploy_ego
from pyoverture.deployutils import deploy_minio
from pyoverture.deployutils import deploy_score_server
from pyoverture.deployutils import initialize_s3_bucket_minio
from pyoverture.deployutils import deploy_song_server


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
                    tmp_public_key, tmp_private_key, remote_private_key, nfs_ip, nfs_dest, nfs_origin,
                    reset_login_vm=False, create_new_keys=True):
    # Could not manage to import a new image into the datastore in an automated way
    #  By now, it must be done manually with the graphical interface
    #  Apps -> Look for the desired distribution (in this case, "ubuntu" in the searcher and "Ubuntu Minimal 18.04 - KVM
    #  -> Click into the cloud icon -> Set up a name, select the local datastore (BSC-EUCC Images) -> Download
    #  In case this must change, add an other value in the class VirtualImages

    # First of all, we need to create a temporal ssh key to perform the connections to the base image

    if create_new_keys:
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
    base_master_vm = VirtualMachine(base_template_master, "overture_base_vm_master", public_ip=public_ip_login_node,
                                    base_user=base_user)
    base_master_vm.instantiate(cloud_session=cloud_session, reset_image=reset_login_vm)
    base_master_vm.set_vm_conn_private_key(tmp_private_key)
    base_master_vm.wait_until_running()
    base_master_vm.set_vm_private_key(tmp_private_key, remote_private_key)

    apt_get_update(base_master_vm)
    install_docker_dependencies(base_master_vm)

    install_nfs_dependencies(base_master_vm)
    mount_nfs(base_master_vm, nfs_ip, nfs_dest, nfs_origin)

    # If we shutdown the master node, the public IP stop being available
    # base_master_vm_id = one.vm.action("poweroff", one.vmpool.info(-1, base_master_vm_id,
    # base_master_vm_id, -1).VM[0].ID)

    base_postgres_song_vm = VirtualMachine(base_template_slaves, "overture_base_vm_postgres_song",
                                           public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_postgres_song_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_postgres_song_vm.set_vm_conn_private_key(tmp_private_key)
        base_postgres_song_vm.wait_until_running()
        base_postgres_song_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_postgres_song_vm)
        install_docker_dependencies(base_postgres_song_vm)
        install_nfs_dependencies(base_postgres_song_vm)
        mount_nfs(base_postgres_song_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_postgres_song_vm.terminate()
        raise e

    base_postgres_ego_vm = VirtualMachine(base_template_slaves, "overture_base_vm_postgres_ego",
                                          public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_postgres_ego_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_postgres_ego_vm.set_vm_conn_private_key(tmp_private_key)
        base_postgres_ego_vm.wait_until_running()
        base_postgres_ego_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_postgres_ego_vm)
        install_docker_dependencies(base_postgres_ego_vm)
        install_nfs_dependencies(base_postgres_ego_vm)
        mount_nfs(base_postgres_song_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_postgres_ego_vm.terminate()
        raise e

    base_minio_score_vm = VirtualMachine(base_template_slaves, "overture_base_vm_minio_score",
                                         public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_minio_score_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_minio_score_vm.set_vm_conn_private_key(tmp_private_key)
        base_minio_score_vm.wait_until_running()
        base_minio_score_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_minio_score_vm)
        install_docker_dependencies(base_minio_score_vm)
        install_nfs_dependencies(base_minio_score_vm)
        mount_nfs(base_minio_score_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_minio_score_vm.terminate()
        raise e

    base_ego_vm = VirtualMachine(base_template_slaves, "overture_base_vm_ego", public_ip=public_ip_login_node,
                                 base_user=base_user)
    try:
        base_ego_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_ego_vm.set_vm_conn_private_key(tmp_private_key)
        base_ego_vm.wait_until_running()
        base_ego_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_ego_vm)
        install_docker_dependencies(base_ego_vm)
        install_nfs_dependencies(base_ego_vm)
        mount_nfs(base_ego_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_ego_vm.terminate()
        raise e

    base_song_vm = VirtualMachine(base_template_slaves, "overture_base_vm_song", public_ip=public_ip_login_node,
                                  base_user=base_user)
    try:
        base_song_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_song_vm.set_vm_conn_private_key(tmp_private_key)
        base_song_vm.wait_until_running()
        base_song_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_song_vm)
        install_docker_dependencies(base_song_vm)
        install_nfs_dependencies(base_song_vm)
        mount_nfs(base_song_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_song_vm.terminate()
        raise e

    base_score_vm = VirtualMachine(base_template_slaves, "overture_base_vm_score", public_ip=public_ip_login_node,
                                   base_user=base_user)
    try:
        base_score_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_score_vm.set_vm_conn_private_key(tmp_private_key)
        base_score_vm.wait_until_running()
        base_score_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_score_vm)
        install_docker_dependencies(base_score_vm)
        install_nfs_dependencies(base_score_vm)
        mount_nfs(base_score_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_score_vm.terminate()
        raise e

    base_all_in_one_vm = VirtualMachine(base_template_slaves, "overture_base_vm_all_in_one",
                                        public_ip=public_ip_login_node, base_user=base_user)
    try:
        base_all_in_one_vm.instantiate(cloud_session=cloud_session, check_name=True)
        base_all_in_one_vm.set_vm_conn_private_key(tmp_private_key)
        base_all_in_one_vm.wait_until_running()
        base_all_in_one_vm.set_vm_private_key(tmp_private_key, remote_private_key)
        apt_get_update(base_all_in_one_vm)
        install_docker_dependencies(base_all_in_one_vm)
        install_nfs_dependencies(base_all_in_one_vm)
        mount_nfs(base_all_in_one_vm, nfs_ip, nfs_dest, nfs_origin)
    except Exception as e:
        print(e)
        base_all_in_one_vm.terminate()
        raise e

    # return base_song_vm, base_score_vm, base_postgres_song_vm, base_all_in_one_vm
    return \
        base_postgres_song_vm, base_postgres_ego_vm, base_minio_score_vm, base_ego_vm, base_score_vm, base_song_vm, \
        base_all_in_one_vm


def main(server_address, cloud_user, cloud_password, reset_login_vm=False):
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
    # https://github.com/fabric/fabric/issues/1492
    # Due to a fabric limitation, we MUST store the private key with this name
    remote_private_key = "/home/" + base_user + "/.ssh/id_rsa"
    host_working_path = "/mnt/nfs/overture_working_dir/"

    cloud_session = CloudSession(server_address, cloud_user, cloud_password)

    # song_vm, score_vm, postgres_song_vm, base_all_in_one_vm = create_machines(cloud_session, base_user,
    (base_postgres_song_vm, base_postgres_ego_vm, base_minio_score_vm, base_ego_vm, base_score_vm, base_song_vm,
     base_all_in_one_vm
     ) = create_machines(
        cloud_session, base_user, base_pass, public_ip_login_node, public_network, private_network, tmp_public_key,
        tmp_private_key, remote_private_key, nfs_ip, nfs_dest, nfs_origin, reset_login_vm=reset_login_vm,
        create_new_keys=False)

    song_postgres_name = "song"
    song_postgres_username = "postgres"
    song_postgres_password = "password"
    song_postgres_port = "5432"
    song_postgres_base_image = "postgres:9.6"
    song_postgres_init_file = Path("/mnt/nfs/overture_files/song-db/song-init.sql")
    song_postgres_folder_working_path = host_working_path + "/song_db/"

    deploy_postgres(base_postgres_song_vm, song_postgres_username, song_postgres_password, song_postgres_name,
                    song_postgres_port, song_postgres_folder_working_path, song_postgres_init_file,
                    song_postgres_base_image, container_name="song_postgres", verbose=True)

    ego_postgres_name = "ego"
    ego_postgres_username = "postgres"
    ego_postgres_password = "password"
    ego_postgres_port = "5432"
    ego_postgres_base_image = "postgres:9.5"
    ego_postgres_init_file = Path("/mnt/nfs/overture_files/ego-db/init.sql")
    ego_postgres_folder_working_path = host_working_path + "/ego_db/"
    ego_postgres_private_ip = base_postgres_ego_vm.get_private_ip()

    deploy_postgres(base_postgres_ego_vm, ego_postgres_username, ego_postgres_password, ego_postgres_name,
                    ego_postgres_port, ego_postgres_folder_working_path, ego_postgres_init_file,
                    ego_postgres_base_image, container_name="ego_postgres", verbose=True)

    ego_port = "9082"
    ego_base_image = "overture/ego:2.9.0"

    deploy_ego(base_ego_vm, ego_port, ego_postgres_private_ip, ego_postgres_port, ego_postgres_username,
               ego_postgres_password, ego_base_image, container_name="ego_service", verbose=True)

    minio_score_port = "8085"
    minio_score_username = "minio"
    minio_score_password = "minio123"
    minio_score_base_image = "minio/minio:RELEASE.2018-05-11T00-29-24Z"
    minio_score_init_file = Path("/mnt/nfs/overture_files/minio-db/heliograph")
    minio_score_folder_working_path = host_working_path + "/score_db/"
    deploy_minio(base_minio_score_vm, minio_score_port, minio_score_username, minio_score_password,
                 minio_score_base_image, container_name="score_minio")

    aws_cli_base_image = "mesosphere/aws-cli:latest"
    s3_region = "us-east-1"
    s3_name = "oicr.icgc.test"
    minio_private_ip = base_minio_score_vm.get_private_ip()
    initialize_s3_bucket_minio(base_minio_score_vm, minio_score_username, minio_score_password, minio_private_ip,
                               minio_score_port, s3_name, s3_region, minio_score_folder_working_path,
                               minio_score_init_file, aws_cli_base_image)

    score_base_image = "overture/score-server:2.0.1"
    score_port = "8087"
    song_port = "8080"
    song_address = base_song_vm.get_private_ip()
    ego_private_ip = base_ego_vm.get_private_ip()
    auth_url = "http://" + ego_private_ip + ":" + minio_score_port + "/o/check_token/"
    score_username = "score"
    score_password = "scoresecret"
    deploy_score_server(base_score_vm, score_username, score_password, score_port, song_address, song_port, s3_name,
                        minio_private_ip, minio_score_port, minio_score_username, minio_score_password, auth_url,
                        score_base_image, container_name="score_service", verbose=True)

    song_base_image = "overture/song-server:3.0.1"
    song_username = "song"
    song_password = "songsecret"
    song_folder_working_path = host_working_path + "/song_logs/"
    score_private_ip = base_score_vm.get_private_ip()
    score_url = "http://" + score_private_ip + ":" + score_port
    score_token = "f69b726d-d40f-4261-b105-1ec7e6bf04d5"
    postgres_song_url = "jdbc:postgresql://" + base_postgres_song_vm.get_private_ip() + ":" + song_postgres_port \
                        + "/song?stringtype=unspecified"
    deploy_song_server(base_song_vm, song_username, song_password, song_port, song_folder_working_path,
                       song_postgres_username, song_postgres_password, postgres_song_url, score_url, score_token,
                       auth_url, song_base_image, container_name="song_service", verbose=True)
    # deploy_full_test_stack(public_ip_login_node, base_all_in_one_vm, tmp_private_key, base_user, verbose=True)


if __name__ == "__main__":
    username = environ["SL_USER"]
    password = environ["SL_PASS"]
    main("http://slcloud1.bsc.es:2633/RPC2", username, password)

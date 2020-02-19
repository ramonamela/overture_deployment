from fabric import Connection
from pyoverture.utils import run_command_ssh_gateway

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

    print("Download song and install docker and all dependencies", end="")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, first_deploy_script)
    print(out)
    print(err)
    print("Docker compose", end="")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, second_deploy_script)
    print(out)
    print(err)
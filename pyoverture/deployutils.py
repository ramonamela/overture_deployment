"""
def deploy_full_test_stack(public_ip_login_node, base_all_in_one_vm, local_private, base_user, verbose=False):
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
                     "sudo ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose\n" \
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

    # first_deploy_script = download_song + install_docker + install_useful_dependencies
    first_deploy_script = download_song + install_useful_dependencies
    second_deploy_script = install_mandatory_dependencies + run_docker_compose  # + check_server_status

    conn = Connection(host=public_ip_login_node, user="user", connect_kwargs={"key_filename": local_private},
                      forward_agent=True)

    print("Download song and install docker and all dependencies", end="")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, first_deploy_script)
    if verbose:
        print(out)
        print(err)
    print("Docker compose", end="")
    out, err = run_command_ssh_gateway(conn, base_user, private_ip, second_deploy_script)
    if verbose:
        print(out)
        print(err)
"""


def deploy_ego(base_ego_vm, ego_port, db_endpoint, db_port, db_username, db_password, ego_base_image,
               container_name=None, verbose=False):
    deploy_command = \
        "docker run -d --env SERVER_PORT=8080 --env SPRING_DATASOURCE_URL=jdbc:postgresql://" + db_endpoint + ":" \
        + db_port + "/ego?stringtype=unspecified --env SPRING_DATASOURCE_USERNAME=" + db_username + " " \
        "--env SPRING_DATASOURCE_PASSWORD=" + db_password + " --env SPRING_FLYWAY_ENABLED=\"true\" " \
        "--env SPRING_FLYWAY_LOCATIONS=\"classpath:flyway/sql,classpath:db/migration\" " \
        "--env SPRING_PROFILES=\"demo, auth\" --expose 8080 -p " + ego_port + ":8080 "
    if container_name is not None:
        stop_container = "docker stop " + container_name + "\n" \
                                                           "docker container rm " + container_name + "\n"
        try:
            base_ego_vm.run_command(stop_container, print_message="Start ego docker", verbose=verbose)
        except Exception as e:
            if "No such container" not in str(e):
                raise e
        deploy_command += "--name " + container_name + " "
    deploy_command += ego_base_image + " java -jar /usr/bin/ego.jar"
    print("EGO DEPLOY COMMAND")
    print(deploy_command)
    base_ego_vm.run_command(deploy_command, print_message="Deploy the ego service", verbose=verbose)


def deploy_minio(base_minio_vm, minio_port, minio_username, minio_password, minio_base_image, container_name=None,
                 verbose=False):

    deploy_command = \
        "docker run -d --env MINIO_ACCESS_KEY=" + minio_username + " --env MINIO_SECRET_KEY=" + minio_password + " " \
        "-p " + minio_port + ":9000 --health-cmd=\"curl -f http://localhost:9000/minio/health/live\" " \
        "--health-interval=30s --health-timeout=20s --health-retries=3 "

    if container_name is not None:
        stop_container = "docker stop " + container_name + "\n" \
                                                           "docker container rm " + container_name + "\n"
        try:
            base_minio_vm.run_command(stop_container, print_message="Start minio docker", verbose=verbose)
        except Exception as e:
            if "No such container" not in str(e):
                raise e
        deploy_command += "--name " + container_name + " "

    deploy_command += minio_base_image + " server /data"
    base_minio_vm.run_command(deploy_command, print_message="Deploy the ego service", verbose=verbose)


def deploy_postgres(vm, username, password, base_sql_db_name, port, host_working_path,
                    postgres_init_file, postgres_base_image, container_name=None, verbose=False):
    db_name = postgres_init_file.name
    python_command = "from pathlib import Path;" \
                     "from os import symlink;" \
                     "db_working_path = \"" + host_working_path + "\";" \
                     "db_working_dir = Path(db_working_path);" \
                     "db_working_dir.mkdir(parents=True, exist_ok=True);"

    create_folders = "python3 -c \\'" + python_command + "\\'\n"

    vm.run_command(create_folders, print_message="Create all necessary folders", verbose=verbose)
    create_links = "ln -fn " + str(postgres_init_file) + " " + host_working_path + "/" + db_name + "\n"
    vm.run_command(create_links, print_message="Create all necessary links to existent files", verbose=verbose)

    start_docker_command = "docker run -p " + port + ":5432 --env POSTGRES_DB=" + base_sql_db_name + " " \
                                                                                                     "--env " \
                                                                                                     "POSTGRES_USER="\
                           + username + " --env POSTGRES_PASSWORD=" + password + " " \
                           "--expose 5432 -d -v " + host_working_path + ":/docker-entrypoint-initdb.d "
    if container_name is not None:
        stop_container = "docker stop " + container_name + "\n" \
                                                           "docker container rm " + container_name + "\n"
        try:
            vm.run_command(stop_container, print_message="Start postgres docker", verbose=verbose)
        except Exception as e:
            print("TEXT")
            print(str(e))
            if "No such container" not in str(e):
                raise e
        start_docker_command += "--name " + container_name + " "
    start_docker_command += postgres_base_image + "\n"
    print(start_docker_command)
    vm.run_command(start_docker_command, print_message="Start postgres docker", verbose=verbose)


def initialize_s3_bucket_minio(vm, minio_user, minio_pass, minio_ip, minio_port, s3_name, s3_region, host_working_path,
                               minio_init_file, aws_cli_base_image, verbose=False):
    init_command = "docker run --env AWS_ACCESS_KEY_ID=" + minio_user + " --env AWS_SECRET_ACCESS_KEY=" + minio_pass \
                   + " --env AWS_DEFAULT_REGION=" + s3_region + " " + aws_cli_base_image + " --endpoint-url " \
                                                                                           "http://" + minio_ip + ":"\
                   + minio_port + " s3 mb s3://" + s3_name

    print(init_command)
    out, err = vm.run_command(init_command, print_message="Start postgres docker", verbose=verbose)
    print(out)

    db_name = minio_init_file.name
    python_command = "from pathlib import Path;" \
                     "from os import symlink;" \
                     "db_working_path = \"" + host_working_path + "\";" \
                     "db_working_dir = Path(db_working_path);" \
                     "db_working_dir.mkdir(parents=True, exist_ok=True);"

    create_folders = "python3 -c \\'" + python_command + "\\'\n"

    vm.run_command(create_folders, print_message="Create all necessary folders", verbose=verbose)
    create_links = "ln -fn " + str(minio_init_file) + " " + host_working_path + "/" + db_name + "\n"
    vm.run_command(create_links, print_message="Create all necessary links to existent files", verbose=verbose)

    put_command = "docker run --env AWS_ACCESS_KEY_ID=" + minio_user + " --env AWS_SECRET_ACCESS_KEY=" + minio_pass \
                  + " --env AWS_DEFAULT_REGION=" + s3_region + " -v " + host_working_path + ":/score-data "\
                  + aws_cli_base_image + " --endpoint-url http://" + minio_ip + ":" + minio_port \
                  + " s3 cp /score-data/" + str(db_name) + " s3://" + s3_name + "/data/" + db_name
    vm.run_command(put_command, print_message="Create all necessary links to existent files", verbose=verbose)


def deploy_score_server(vm, score_username, score_password, score_port, song_address, song_port, s3_name, s3_endpoint,
                        s3_port, s3_username, s3_password, auth_url, score_base_image, enable_ssl="false",
                        upload_part_size=1073741824, upload_con_timeout=1200000, log_level="debug", verbose=False):
    assert enable_ssl == "false" or enable_ssl == "true"
    deploy_command = "MY_UID=$(id -u) MY_GID=$(id -g) docker run -d " \
                     + "--env SPRING_PROFILES_ACTIVE=amazon,collaboratory,prod,secure " \
                     + "--env SERVER_PORT=8080 " \
                     + "--env OBJECT_SENTINEL=heliograph" \
                     + " --env BUCKET_NAME_OBJECT=" + s3_name \
                     + " --env BUCKET_NAME_STATE=" + s3_name \
                     + " --env COLLABORATORY_DATA_DIRECTORY=data" \
                     + " --env METADATA_URL=http://" + song_address + ":" + song_port \
                     + " --env S3_ENDPOINT=http://" + s3_endpoint + ":" + s3_port \
                     + " --env S3_ACCESSKEY=" + s3_username \
                     + " --env S3_SECRETKEY=" + s3_password \
                     + " --env S3_SIGV4ENABLED=\"true\"" \
                     + " --env AUTH_SERVER_URL=" + auth_url \
                     + " --env AUTH_SERVER_CLIENTID=" + score_username \
                     + " --env AUTH_SERVER_CLIENTSECRET=" + score_password \
                     + " --env AUTH_SERVER_UPLOADSCOPE=score.WRITE" \
                     + " --env AUTH_SERVER_DOWNLOADSCOPE=score.READ" \
                     + " --env SERVER_SSL_ENABLED=\"" + enable_ssl + "\"" \
                     + " --env UPLOAD_PARTSIZE=" + str(upload_part_size) \
                     + " --env UPLOAD_CONNECTION_TIMEOUT=" + str(upload_con_timeout)
    if log_level == "debug":
        deploy_command += " --env LOGGING_LEVEL_BIO_OVERTURE_SCORE_SERVER=DEBUG" \
                          + " --env LOGGING_LEVEL_ORG_APACHE_HTTP_WIRE=DEBUG" \
                          + " --env LOGGING_LEVEL_ORG_APACHE_HTTP_HEADERS=DEBUG"
    deploy_command += " --env ENDPOINTS_DUMP_ENABLED=\"false\"" \
                      + " --env ENDPOINTS_ENV_ENABLED=\"true\"" \
                      + " --env ENDPOINTS_INFO_ENABLED=\"true\""
    deploy_command += " -p " + score_port + ":8080"
    deploy_command += " " + score_base_image
    print(deploy_command)
    out, err = vm.run_command(deploy_command, print_message="Start postgres docker", verbose=verbose)
    print(out)

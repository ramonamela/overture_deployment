#!/bin/bash

#MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/song_logs:/song-client/logs -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env CLIENT_STUDY_ID="ABC123" --env CLIENT_DEBUG="true" --env CLIENT_SERVER_URL="https://84.88.186.194/song_eucancan_bsc" --entrypoint bin/sing overture/song-client:3.0.1 ping

#MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/song_logs:/song-client/logs -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env CLIENT_STUDY_ID="ABC123" --env CLIENT_DEBUG="true" --env CLIENT_SERVER_URL="http://10.32.3.6:8080" --entrypoint bin/sing overture/song-client:3.0.1 ping

#MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/input:/song-client/input -v $(pwd)/logs:/score-client/logs -v $(pwd)/score_out:/score-client/output -v $(pwd)/song_out:/song-vlient/output --env ACCESSTOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env METADATA_URL="http://song-server:8080" --env STORAGE_URL="http://score-server:8080" overture/score:2.0.1 bin/score-client
echo "Check if server is up"
MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/song_logs:/song-client/logs -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env CLIENT_STUDY_ID="ABC123" --env CLIENT_DEBUG="true" --env CLIENT_SERVER_URL="https://eucancan.bsc.es/song_eucancan_bsc" --entrypoint bin/sing overture/song-client:3.0.1 ping

# ./tools/song-client submit -f /song-client/input/exampleVariantCall.json
echo "Submit json containing the description of the payload"
analysis_json=$(MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/song_logs:/song-client/logs -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env CLIENT_STUDY_ID="ABC123" --env CLIENT_DEBUG="true" --env CLIENT_SERVER_URL="https://eucancan.bsc.es/song_eucancan_bsc" --entrypoint bin/sing overture/song-client:3.0.1 submit -f /song-client/input/exampleVariantCall.json)
analysis_id=$(echo ${analysis_json} | sed 's/"/\"/g' | jq .analysisId)
echo "The current analysis id is ${analysis_id}"

echo "Generate the manifest"
MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/song_logs:/song-client/logs -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env CLIENT_STUDY_ID="ABC123" --env CLIENT_DEBUG="true" --env CLIENT_SERVER_URL="https://eucancan.bsc.es/song_eucancan_bsc" --entrypoint bin/sing overture/song-client:3.0.1 manifest -f /song-client/output/manifest.txt -d /song-client/input -a ${analysis_id}

echo "Upload the files"
MY_UID=$(id -u) MY_GID=$(id -g) docker run -v $(pwd)/song_input:/song-client/input -v $(pwd)/score_logs:/score-client/logs -v $(pwd)/score_out:/score-client/output -v $(pwd)/song_out:/song-client/output --env CLIENT_ACCESS_TOKEN="f69b726d-d40f-4261-b105-1ec7e6bf04d5" --env METADATA_URL="https://eucancan.bsc.es/song_eucancan_bsc" --env STORAGE_URL="https://eucancan.bsc.es/score_eucancan_bsc" --entrypoint bin/score-client overture/score:2.0.1 upload --manifest /song-client/output/manifest.txt --force



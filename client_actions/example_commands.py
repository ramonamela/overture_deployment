#!/usr/bin/env python3

from overture_song.model import ApiConfig
from overture_song.client import Api
from overture_song.client import StudyClient
from overture_song.client import Study
from overture_song.entities import *

if __name__ == "__main__":
    api_config = ApiConfig("http://84.88.186.194/song_eucancan_bsc", "ABC123", "f69b726d-d40f-4261-b105-1ec7e6bf04d5")
    api = Api(api_config)
    ## Check that we have access to the server
    print("Access to the server: ", end="")
    print(api.is_alive())

    ## Create the study
    study_client = StudyClient(api)
    if not study_client.has(api_config.study_id):
        print("The study does not exists, creating it")
        study = Study.create(api_config.study_id, "myStudyName", "mySudyDescription", "myStudyOrganization")
        #study_client(study)
    else:
        print("The study already exists")

    ## Create donor
    donor = Donor()
    donor.studyId = api_config.study_id
    donor.donorGender = "male"
    donor.donorSubmitterId = "dsId1"
    donor.set_info("randomDonorField", "someDonorValue")

    ## Create specimen
    specimen = Specimen()
    specimen.specimenClass = "Tumour"
    specimen.specimenSubmitterId = "sp_sub_1"
    specimen.specimenType = "Normal - EBV immortalized"
    specimen.set_info("randomSpecimenField", "someSpecimenValue")

    ## Create sample
    sample = Sample()
    sample.sampleSubmitterId = "ssId1"
    sample.sampleType = "RNA"
    sample.set_info("randomSample1Field", "someSample1Value")

    # File 1
    file1 = File()
    file1.fileName = "myFilename1.bam"
    file1.studyId = api_config.study_id
    file1.fileAccess = "controlled"
    file1.fileMd5sum = "myMd51"
    file1.fileSize = 1234561
    file1.fileType = "VCF"
    file1.set_info("randomFile1Field", "someFile1Value")

    # File 2
    file2 = File()
    file2.fileName = "myFilename2.bam"
    file2.studyId = api_config.study_id
    file2.fileAccess = "controlled"
    file2.fileMd5sum = "myMd52"
    file2.fileSize = 1234562
    file2.fileType = "VCF"
    file2.set_info("randomFile2Field", "someFile2Value")
    
    ## Create SequencingRead experiment entity
    sequencing_read_experiment = SequencingRead()
    sequencing_read_experiment.aligned = True
    sequencing_read_experiment.alignmentTool = "myAlignmentTool"
    sequencing_read_experiment.pairedEnd = True
    sequencing_read_experiment.insertSize = 0
    sequencing_read_experiment.libraryStrategy = "WXS"
    sequencing_read_experiment.referenceGenome = "GR37"
    sequencing_read_experiment.set_info("randomSRField", "someSRValue")
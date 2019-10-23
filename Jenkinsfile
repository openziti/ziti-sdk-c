pipeline {
  agent { docker { image 'netfoundry/ziti-build-pipeline:latest'}}
  stages {
    stage("Setup") {
      steps {
        sh 'git submodule update --init --recursive'
        sh 'git submodule status --recursive'
      }
    }
    stage('Tests') {
      steps {
        sh 'mkdir build-test'
        dir('build-test') {
            sh 'cmake ..'
            sh 'cmake --build . --target all_tests'
            sh 'ctest --no-compress-output -T Test'
        }
      }
    }
    stage('Build all platforms') {
      steps {
        sh '/bin/pwd'
        sh 'ls -al'
        sh 'uber-build.sh'
      }
    }
  }
  post {
    always {
      // Archive the CTest xml output
      archiveArtifacts (
        artifacts: 'build-test/Testing/**/*.xml',
        fingerprint: true
      )

      // Process the CTest xml output with the xUnit plugin
      xunit (
        testTimeMargin: '3000',
        thresholdMode: 1,
        thresholds: [
          skipped(failureThreshold: '0'),
          failed(failureThreshold: '0')
        ],
      tools: [CTest(
          pattern: 'build-test/Testing/**/*.xml',
          deleteOutputFiles: true,
          failIfNotNew: false,
          skipNoTestFiles: true,
          stopProcessingIfError: true
        )]
      )

      // Clear the source and build dirs before next run
      deleteDir()
    }
  }
}
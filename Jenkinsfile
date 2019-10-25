pipeline {
  agent any //{ docker { image 'netfoundry/ziti-build-pipeline:latest'}}

  stages {
//     stage("Setup") {
//       steps {
//         sh 'git submodule update --init --recursive'
//         sh 'git submodule status --recursive'
//         sh 'git fetch --verbose --tags'
//       }
//     }
//     stage('Tagging') {
//       when { branch 'master'}
//       steps {
//         echo 'creating new tag'
//       }
//     }
//     stage('Tests') {
//       steps {
//         sh 'mkdir build-test'
//         dir('build-test') {
//             sh 'cmake ..'
//             sh 'cmake --build . --target all_tests'
//             sh 'ctest --no-compress-output -T Test'
//         }
//       }
//       post {
//         always {
//           // Archive the CTest xml output
//           archiveArtifacts (
//             artifacts: 'build-test/Testing/**/*.xml',
//             fingerprint: true
//           )
//
//           // Process the CTest xml output with the xUnit plugin
//           xunit (
//             testTimeMargin: '3000',
//             thresholdMode: 1,
//             thresholds: [
//               skipped(failureThreshold: '0'),
//               failed(failureThreshold: '0')
//             ],
//           tools: [CTest(
//               pattern: 'build-test/Testing/**/*.xml',
//               deleteOutputFiles: true,
//               failIfNotNew: false,
//               skipNoTestFiles: true,
//               stopProcessingIfError: true
//             )]
//           )
//         }
//       }
//     }
//     stage('Build all platforms') {
//       failFast true
//       parallel {
//         stage('Linux-x86_64') {
//           steps {
//             echo "building ${STAGE_NAME}"
//             sh "mkdir -p build-${STAGE_NAME}"
//             dir("build-${STAGE_NAME}") {
//                sh 'cmake -DCMAKE_BUILD_TYPE=Debug ..'
//                sh 'cmake --build . --target package --target publish'
//             }
//           }
//         }
//         stage('Linux-arm') {
//           steps {
//             echo "building ${STAGE_NAME}"
//             sh "mkdir -p build-${STAGE_NAME}"
//             dir("build-${STAGE_NAME}") {
//                sh 'cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_TOOLCHAIN_FILE=../toolchains/${STAGE_NAME}.cmake ..'
//                sh 'cmake --build . --target package --target publish'
//             }
//           }
//         }
//       }
//     }
    stage('Publish') {
      steps {
        //sh "./make_publish_spec.sh"
        script {
            //sh "cat publish.json"
            rtUpload {serverId: 'ziti-uploads',
              // specPath: "./publish.json"
              spec:
                        """{
                        "files": [
                        {
                            "pattern": "./LICENSE",
                            "target": "ziti-snapshot/testfile/"
                        }
                        ]
                        }"""
            }
        }
      }
    }
  }
}
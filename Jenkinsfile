pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Setup Python') {
            steps {
                script {
                    // Install Python and virtualenv
                    sh 'sudo apt-get update'
                    sh 'sudo apt-get install -y python3 python3-venv'
                }
            }
        }

        stage('Create Virtual Environment') {
            steps {
                script {
                    // Create a virtual environment
                    sh 'python3 -m venv venv'
                }
            }
        }


        stage('Run Server') {
            steps {
                script {
                    // Run Django development server
                    sh '''
                    . venv/bin/activate
                    python3 manage.py runserver 
                    '''
                }
            }
        }
    }

    post {
        always {
            // Cleanup
            sh 'rm -rf venv'
        }
        success {
            echo 'Build was successful!'
        }
        failure {
            echo 'Build failed!'
        }
    }
}

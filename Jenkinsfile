pipeline {
     agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        
        stage('Install Dependencies') {
            steps {
                script {
                    // Install dependencies
                    sh '''
                    npm install python3 python3-venv
                    . venv/bin/activate
                    pip install -r requirements.txt
                    npm install redis-server
                    '''
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
                    redis-server
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

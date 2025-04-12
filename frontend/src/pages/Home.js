import React, { useState, useEffect } from 'react';
import {
  Box,
  Container,
  Heading,
  Text,
  SimpleGrid,
  Flex,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Alert,
  AlertIcon,
  useColorModeValue,
  Icon,
  Divider,
} from '@chakra-ui/react';
import { FaShieldAlt, FaCloudUploadAlt, FaFileAlt, FaHistory } from 'react-icons/fa';
import FileUpload from '../components/FileUpload';
import { getHealthStatus } from '../utils/api';

const FeatureCard = ({ title, icon, children, ...rest }) => {
  const bg = useColorModeValue('white', 'gray.800');
  const borderColor = useColorModeValue('gray.200', 'gray.700');

  return (
    <Box
      p={5}
      shadow="md"
      borderWidth="1px"
      borderRadius="lg"
      bg={bg}
      borderColor={borderColor}
      {...rest}
    >
      <Flex align="center" mb={3}>
        <Icon as={icon} w={6} h={6} color="brand.500" mr={2} />
        <Heading size="md">{title}</Heading>
      </Flex>
      <Text>{children}</Text>
    </Box>
  );
};

const Home = () => {
  const [apiStatus, setApiStatus] = useState('loading');
  
  useEffect(() => {
    const checkStatus = async () => {
      try {
        const status = await getHealthStatus();
        if (status.status === 'ok') {
          setApiStatus('online');
        } else {
          setApiStatus('offline');
        }
      } catch (error) {
        setApiStatus('offline');
      }
    };
    
    checkStatus();
  }, []);

  return (
    <Container maxW="container.xl" py={8}>
      <Box textAlign="center" mb={10}>
        <Heading
          as="h1"
          size="2xl"
          fontWeight="bold"
          color={useColorModeValue('gray.800', 'white')}
          mb={3}
        >
          Static Malware Analyzer
        </Heading>
        <Text fontSize="xl" color={useColorModeValue('gray.600', 'gray.300')}>
          Secure, efficient static analysis for EXE and PDF files
        </Text>
      </Box>

      {apiStatus === 'offline' && (
        <Alert status="error" mb={6} borderRadius="md">
          <AlertIcon />
          The analysis service is currently offline. Please try again later.
        </Alert>
      )}

      <SimpleGrid columns={{ base: 1, md: 2 }} spacing={10} mb={12}>
        <Box>
          <SimpleGrid columns={{ base: 1, sm: 1 }} spacing={5} mb={6}>
            <FeatureCard title="Advanced Static Analysis" icon={FaShieldAlt}>
              Leverage machine learning and static analysis techniques to detect malware 
              without execution, providing comprehensive security insights.
            </FeatureCard>
            
            <FeatureCard title="Instant File Scanning" icon={FaCloudUploadAlt}>
              Upload EXE and PDF files for instant analysis. Get detailed reports on potential 
              threats, suspicious indicators, and security recommendations.
            </FeatureCard>
            
            <FeatureCard title="Detailed Reports" icon={FaFileAlt}>
              Receive comprehensive reports with file properties, malware scores, detected indicators, 
              and technical analysis of file structure and contents.
            </FeatureCard>
            
            <FeatureCard title="Analysis History" icon={FaHistory}>
              Access your past analyses with a complete history of all scanned files, 
              making it easy to track and monitor security over time.
            </FeatureCard>
          </SimpleGrid>
        </Box>

        <Box>
          <FileUpload />
        </Box>
      </SimpleGrid>

      <Divider my={12} />

      <Box mb={12}>
        <Heading as="h2" size="lg" mb={6} textAlign="center">
          How It Works
        </Heading>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={10}>
          <Box textAlign="center">
            <Flex
              w={16}
              h={16}
              align="center"
              justify="center"
              color="white"
              rounded="full"
              bg="brand.500"
              mb={4}
              mx="auto"
            >
              <Icon as={FaCloudUploadAlt} w={8} h={8} />
            </Flex>
            <Heading as="h3" size="md" mb={2}>
              1. Upload File
            </Heading>
            <Text>
              Select an EXE or PDF file to upload for analysis. Files are securely handled and
              processed in isolation.
            </Text>
          </Box>

          <Box textAlign="center">
            <Flex
              w={16}
              h={16}
              align="center"
              justify="center"
              color="white"
              rounded="full"
              bg="brand.500"
              mb={4}
              mx="auto"
            >
              <Icon as={FaShieldAlt} w={8} h={8} />
            </Flex>
            <Heading as="h3" size="md" mb={2}>
              2. Automated Analysis
            </Heading>
            <Text>
              Our system performs static analysis using AI/ML techniques to identify malicious 
              patterns and behaviors without executing the code.
            </Text>
          </Box>

          <Box textAlign="center">
            <Flex
              w={16}
              h={16}
              align="center"
              justify="center"
              color="white"
              rounded="full"
              bg="brand.500"
              mb={4}
              mx="auto"
            >
              <Icon as={FaFileAlt} w={8} h={8} />
            </Flex>
            <Heading as="h3" size="md" mb={2}>
              3. Comprehensive Report
            </Heading>
            <Text>
              View and download detailed reports with malware scores, detected threats, 
              file characteristics, and security recommendations.
            </Text>
          </Box>
        </SimpleGrid>
      </Box>

      <Box bg={useColorModeValue('gray.100', 'gray.700')} p={6} borderRadius="lg">
        <Heading as="h2" size="md" mb={4} textAlign="center">
          System Status
        </Heading>
        <SimpleGrid columns={{ base: 1, md: 3 }} spacing={5}>
          <Stat textAlign="center">
            <StatLabel>API Status</StatLabel>
            <StatNumber color={apiStatus === 'online' ? 'green.500' : 'red.500'}>
              {apiStatus === 'online' ? 'Online' : apiStatus === 'loading' ? 'Checking...' : 'Offline'}
            </StatNumber>
          </Stat>

          <Stat textAlign="center">
            <StatLabel>Supported Files</StatLabel>
            <StatNumber>EXE, PDF</StatNumber>
            <StatHelpText>Maximum size: 50MB</StatHelpText>
          </Stat>

          <Stat textAlign="center">
            <StatLabel>Analysis Engine</StatLabel>
            <StatNumber>v1.0</StatNumber>
            <StatHelpText>ML-based static analysis</StatHelpText>
          </Stat>
        </SimpleGrid>
      </Box>
    </Container>
  );
};

export default Home;
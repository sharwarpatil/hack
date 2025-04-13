// import React, { useState, useEffect } from 'react';
// import { useParams, useNavigate } from 'react-router-dom';
// import {
//   Box,
//   Container,
//   Heading,
//   Text,
//   Button,
//   Flex,
//   Spinner,
//   Alert,
//   AlertIcon,
//   AlertTitle,
//   AlertDescription,
//   useColorModeValue,
//   useToast,
// } from '@chakra-ui/react';
// import { ArrowBackIcon, RepeatIcon } from '@chakra-ui/icons';
// import AnalysisReport from '../components/AnalysisReport';
// import { getAnalysisStatus, getAnalysisResult } from '../utils/api';

// const Analysis = () => {
//   const { taskId } = useParams();
//   const navigate = useNavigate();
//   const toast = useToast();

//   const [status, setStatus] = useState('loading');
//   const [result, setResult] = useState(null);
//   const [error, setError] = useState(null);
//   const [pollingInterval, setPollingInterval] = useState(null);

//   const bgColor = useColorModeValue('white', 'gray.800');

//   // Function to fetch analysis status
//   const fetchStatus = async () => {
//     try {
//       const statusData = await getAnalysisStatus(taskId);
//       setStatus(statusData.status);

//       // If analysis is completed, fetch results
//       if (statusData.status === 'completed') {
//         fetchResults();

//         // Clear polling interval
//         if (pollingInterval) {
//           clearInterval(pollingInterval);
//           setPollingInterval(null);
//         }
//       } else if (statusData.status === 'failed') {
//         setError('Analysis failed. Please try again with another file.');

//         // Clear polling interval
//         if (pollingInterval) {
//           clearInterval(pollingInterval);
//           setPollingInterval(null);
//         }
//       }
//     } catch (error) {
//       console.error('Error fetching status:', error);
//       setError('Error fetching analysis status. Please try again.');
//       setStatus('error');

//       // Clear polling interval
//       if (pollingInterval) {
//         clearInterval(pollingInterval);
//         setPollingInterval(null);
//       }
//     }
//   };

//   // Function to fetch analysis results
//   const fetchResults = async () => {
//     try {
//       const resultData = await getAnalysisResult(taskId);
//       setResult(resultData);
//       setStatus('completed');
//     } catch (error) {
//       console.error('Error fetching results:', error);
//       setError('Error fetching analysis results. Please try again.');
//       setStatus('error');
//     }
//   };

//   // Initial fetch and set up polling
//   useEffect(() => {
//     fetchStatus();

//     // Set up polling for status updates (every 3 seconds)
//     const interval = setInterval(fetchStatus, 3000);
//     setPollingInterval(interval);

//     // Cleanup function
//     return () => {
//       if (pollingInterval) {
//         clearInterval(pollingInterval);
//       }
//     };
//   }, [taskId]); // eslint-disable-line react-hooks/exhaustive-deps

//   // Function to handle retry
//   const handleRetry = () => {
//     setStatus('loading');
//     setError(null);
//     fetchStatus();
//   };

//   // Function to navigate back to home
//   const handleBack = () => {
//     navigate('/');
//   };

//   // Render loading state
//   if (status === 'loading' || status === 'processing' || status === 'queued') {
//     return (
//       <Container maxW="container.xl" py={8}>
//         <Box mb={5}>
//           <Button leftIcon={<ArrowBackIcon />} onClick={handleBack} colorScheme="brand" variant="outline">
//             Back to Home
//           </Button>
//         </Box>

//         <Box
//           p={8}
//           shadow="md"
//           borderWidth="1px"
//           borderRadius="lg"
//           bg={bgColor}
//           textAlign="center"
//         >
//           <Flex direction="column" align="center" justify="center">
//             <Spinner
//               thickness="4px"
//               speed="0.65s"
//               emptyColor="gray.200"
//               color="brand.500"
//               size="xl"
//               mb={4}
//             />
//             <Heading size="lg" mb={2}>
//               {status === 'loading' ? 'Loading Analysis...' : status === 'processing' ? 'Processing File...' : 'Queued for Analysis...'}
//             </Heading>
//             <Text color="gray.500" mb={4}>
//               Task ID: {taskId}
//             </Text>
//             <Text mb={6}>
//               {status === 'loading'
//                 ? 'Retrieving analysis status...'
//                 : status === 'processing'
//                   ? 'Your file is being analyzed. This may take a minute...'
//                   : 'Your file is queued for analysis and will begin shortly...'}
//             </Text>
//           </Flex>
//         </Box>
//       </Container>
//     );
//   }

//   // Render error state
//   if (status === 'error' || error) {
//     return (
//       <Container maxW="container.xl" py={8}>
//         <Box mb={5}>
//           <Button leftIcon={<ArrowBackIcon />} onClick={handleBack} colorScheme="brand" variant="outline">
//             Back to Home
//           </Button>
//         </Box>

//         <Box p={8} shadow="md" borderWidth="1px" borderRadius="lg" bg={bgColor}>
//           <Alert
//             status="error"
//             variant="subtle"
//             flexDirection="column"
//             alignItems="center"
//             justifyContent="center"
//             textAlign="center"
//             height="200px"
//             borderRadius="md"
//           >
//             <AlertIcon boxSize="40px" mr={0} />
//             <AlertTitle mt={4} mb={1} fontSize="lg">
//               Analysis Error
//             </AlertTitle>
//             <AlertDescription maxWidth="md">
//               {error || 'An error occurred during the analysis. Please try again.'}
//             </AlertDescription>
//             <Button
//               leftIcon={<RepeatIcon />}
//               colorScheme="red"
//               variant="outline"
//               mt={4}
//               onClick={handleRetry}
//             >
//               Retry
//             </Button>
//           </Alert>
//         </Box>
//       </Container>
//     );
//   }

//   // Render completed state with results
//   return (
//     <Container maxW="container.xl" py={8}>
//       <Box mb={5}>
//         <Button leftIcon={<ArrowBackIcon />} onClick={handleBack} colorScheme="brand" variant="outline">
//           Back to Home
//         </Button>
//       </Box>

//       <AnalysisReport analysis={result?.details} status={status} taskId={taskId} />
//     </Container>
//   );
// };

// export default Analysis;
// Updated Analysis.js with improved error handling
import React, { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Box,
  Container,
  Heading,
  Text,
  Button,
  Flex,
  Spinner,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  useColorModeValue,
  useToast,
} from "@chakra-ui/react";
import { ArrowBackIcon, RepeatIcon } from "@chakra-ui/icons";
import AnalysisReport from "../components/AnalysisReport";
import { getAnalysisStatus, getAnalysisResult } from "../utils/api";

const Analysis = () => {
  const { taskId } = useParams();
  const navigate = useNavigate();
  const toast = useToast();

  const [status, setStatus] = useState("loading");
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [pollingInterval, setPollingInterval] = useState(null);
  const [retryCount, setRetryCount] = useState(0);
  const maxRetries = 3;

  const bgColor = useColorModeValue("white", "gray.800");

  // Function to fetch analysis status with retry logic
  const fetchStatus = useCallback(async () => {
    try {
      console.log(`Fetching status for task: ${taskId}`);
      const statusData = await getAnalysisStatus(taskId);
      console.log("Status data received:", statusData);

      if (!statusData) {
        throw new Error("No status data received");
      }

      setStatus(statusData.status);
      setRetryCount(0); // Reset retry count on success

      // If analysis is completed, fetch results
      if (statusData.status === "completed") {
        fetchResults();

        // Clear polling interval
        if (pollingInterval) {
          clearInterval(pollingInterval);
          setPollingInterval(null);
        }
      } else if (statusData.status === "failed") {
        setError("Analysis failed. Please try again with another file.");

        // Clear polling interval
        if (pollingInterval) {
          clearInterval(pollingInterval);
          setPollingInterval(null);
        }
      }
    } catch (error) {
      console.error("Error fetching status:", error);

      // Implement retry logic
      if (retryCount < maxRetries) {
        setRetryCount((prev) => prev + 1);
        toast({
          title: "Connection issue",
          description: `Retrying... (${retryCount + 1}/${maxRetries})`,
          status: "warning",
          duration: 2000,
          isClosable: true,
        });
      } else {
        setError("Error fetching analysis status. Please try again.");
        setStatus("error");

        // Clear polling interval
        if (pollingInterval) {
          clearInterval(pollingInterval);
          setPollingInterval(null);
        }
      }
    }
  }, [taskId, pollingInterval, retryCount]);

  // Function to fetch analysis results
  const fetchResults = async () => {
    try {
      console.log(`Fetching results for task: ${taskId}`);
      const resultData = await getAnalysisResult(taskId);
      console.log("Result data received:", resultData);

      if (!resultData) {
        throw new Error("No result data received");
      }

      setResult(resultData);
      setStatus("completed");
    } catch (error) {
      console.error("Error fetching results:", error);
      setError("Error fetching analysis results. Please try again.");
      setStatus("error");
    }
  };

  // Initial fetch and set up polling
  useEffect(() => {
    // Initial fetch
    fetchStatus();

    // Set up polling for status updates (every 3 seconds)
    const interval = setInterval(fetchStatus, 3000);
    setPollingInterval(interval);

    // Cleanup function
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [fetchStatus]);

  // Function to handle retry
  const handleRetry = () => {
    setStatus("loading");
    setError(null);
    setRetryCount(0);
    fetchStatus();

    // Set up polling again
    const interval = setInterval(fetchStatus, 3000);
    setPollingInterval(interval);
  };

  // Function to navigate back to home
  const handleBack = () => {
    navigate("/");
  };

  // Render loading state
  if (status === "loading" || status === "processing" || status === "queued") {
    return (
      <Container maxW="container.xl" py={8}>
        <Box mb={5}>
          <Button
            leftIcon={<ArrowBackIcon />}
            onClick={handleBack}
            colorScheme="brand"
            variant="outline"
          >
            Back to Home
          </Button>
        </Box>

        <Box
          p={8}
          shadow="md"
          borderWidth="1px"
          borderRadius="lg"
          bg={bgColor}
          textAlign="center"
        >
          <Flex direction="column" align="center" justify="center">
            <Spinner
              thickness="4px"
              speed="0.65s"
              emptyColor="gray.200"
              color="brand.500"
              size="xl"
              mb={4}
            />
            <Heading size="lg" mb={2}>
              {status === "loading"
                ? "Loading Analysis..."
                : status === "processing"
                ? "Processing File..."
                : "Queued for Analysis..."}
            </Heading>
            <Text color="gray.500" mb={4}>
              Task ID: {taskId}
            </Text>
            <Text mb={6}>
              {status === "loading"
                ? "Retrieving analysis status..."
                : status === "processing"
                ? "Your file is being analyzed. This may take a minute..."
                : "Your file is queued for analysis and will begin shortly..."}
            </Text>
          </Flex>
        </Box>
      </Container>
    );
  }

  // Render error state
  if (status === "error" || error) {
    return (
      <Container maxW="container.xl" py={8}>
        <Box mb={5}>
          <Button
            leftIcon={<ArrowBackIcon />}
            onClick={handleBack}
            colorScheme="brand"
            variant="outline"
          >
            Back to Home
          </Button>
        </Box>

        <Box p={8} shadow="md" borderWidth="1px" borderRadius="lg" bg={bgColor}>
          <Alert
            status="error"
            variant="subtle"
            flexDirection="column"
            alignItems="center"
            justifyContent="center"
            textAlign="center"
            height="200px"
            borderRadius="md"
          >
            <AlertIcon boxSize="40px" mr={0} />
            <AlertTitle mt={4} mb={1} fontSize="lg">
              Analysis Error
            </AlertTitle>
            <AlertDescription maxWidth="md">
              {error ||
                "An error occurred during the analysis. Please try again."}
            </AlertDescription>
            <Button
              leftIcon={<RepeatIcon />}
              colorScheme="red"
              variant="outline"
              mt={4}
              onClick={handleRetry}
            >
              Retry
            </Button>
          </Alert>
        </Box>
      </Container>
    );
  }

  // Render completed state with results
  return (
    <Container maxW="container.xl" py={8}>
      <Box mb={5}>
        <Button
          leftIcon={<ArrowBackIcon />}
          onClick={handleBack}
          colorScheme="brand"
          variant="outline"
        >
          Back to Home
        </Button>
      </Box>

      <AnalysisReport
        analysis={result?.details}
        status={status}
        taskId={taskId}
      />
    </Container>
  );
};

export default Analysis;

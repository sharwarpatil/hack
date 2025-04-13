// Updated FileUpload.js with proper handling for both PDF and EXE files

import React, { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  Box,
  Button,
  FormControl,
  FormLabel,
  Input,
  VStack,
  Text,
  useToast,
  Progress,
  Flex,
  Icon,
  Radio,
  RadioGroup,
  Stack,
  Alert,
  AlertIcon,
  AlertTitle,
  AlertDescription,
  CloseButton,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
} from "@chakra-ui/react";
import { AttachmentIcon, WarningIcon } from "@chakra-ui/icons";
import { FaPlay } from "react-icons/fa";
import { uploadFile } from "../utils/api";

const FileUpload = () => {
  const [file, setFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [analysisType, setAnalysisType] = useState("full");
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState(0);

  const fileInputRef = useRef(null);
  const dynamicFileInputRef = useRef(null);
  const toast = useToast();
  const navigate = useNavigate();

  const handleFileChange = (e, isDynamic = false) => {
    if (e.target.files.length > 0) {
      const selectedFile = e.target.files[0];

      // Check file type
      const fileExtension = selectedFile.name.split(".").pop().toLowerCase();

      if (isDynamic) {
        // Dynamic analysis only accepts EXE
        if (fileExtension !== "exe") {
          setError("Dynamic analysis is only available for EXE files.");
          setFile(null);
          return;
        }
      } else {
        // Static analysis accepts both EXE and PDF
        if (fileExtension !== "exe" && fileExtension !== "pdf") {
          setError("Only EXE and PDF files are supported for static analysis.");
          setFile(null);
          return;
        }
      }

      // Check file size (50MB limit)
      if (selectedFile.size > 50 * 1024 * 1024) {
        setError("File size exceeds the 50MB limit.");
        setFile(null);
        return;
      }

      setFile(selectedFile);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a file to upload.");
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);

    try {
      // Determine analysis type
      const analysisMode = activeTab === 0 ? analysisType : "dynamic";

      // Simulate progress
      const progressInterval = setInterval(() => {
        setUploadProgress((prev) => {
          if (prev >= 90) {
            clearInterval(progressInterval);
            return 90;
          }
          return prev + 10;
        });
      }, 300);

      // Upload file
      const response = await uploadFile(file, analysisMode);

      clearInterval(progressInterval);
      setUploadProgress(100);

      // Success notification
      toast({
        title: "File uploaded successfully.",
        description: `Your file has been uploaded and is being analyzed with ${
          activeTab === 0 ? analysisType : "dynamic"
        } analysis.`,
        status: "success",
        duration: 5000,
        isClosable: true,
      });

      // Navigate to analysis page
      setTimeout(() => {
        navigate(`/analysis/${response.task_id}`);
      }, 1000);
    } catch (error) {
      console.error("Upload error:", error);
      setError(
        error.response?.data?.detail || "An error occurred during upload."
      );

      toast({
        title: "Upload failed.",
        description:
          error.response?.data?.detail || "An error occurred during upload.",
        status: "error",
        duration: 5000,
        isClosable: true,
      });
    } finally {
      setIsUploading(false);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const handleDrop = (e, isDynamic = false) => {
    e.preventDefault();

    if (e.dataTransfer.files.length > 0) {
      const droppedFile = e.dataTransfer.files[0];

      // Check file type
      const fileExtension = droppedFile.name.split(".").pop().toLowerCase();

      if (isDynamic) {
        // Dynamic analysis only accepts EXE
        if (fileExtension !== "exe") {
          setError("Dynamic analysis is only available for EXE files.");
          return;
        }
      } else {
        // Static analysis accepts both EXE and PDF
        if (fileExtension !== "exe" && fileExtension !== "pdf") {
          setError("Only EXE and PDF files are supported for static analysis.");
          return;
        }
      }

      // Check file size
      if (droppedFile.size > 50 * 1024 * 1024) {
        setError("File size exceeds the 50MB limit.");
        return;
      }

      setFile(droppedFile);
      setError(null);
    }
  };

  const resetFile = () => {
    setFile(null);
    setError(null);
  };

  return (
    <Box p={5} borderWidth={1} borderRadius="lg" boxShadow="md">
      <VStack spacing={5} align="stretch">
        <Tabs
          isFitted
          variant="enclosed"
          colorScheme="brand"
          index={activeTab}
          onChange={(index) => {
            setActiveTab(index);
            resetFile();
          }}
        >
          <TabList mb="1em">
            <Tab>Static Analysis</Tab>
            <Tab>Dynamic Analysis</Tab>
          </TabList>

          <TabPanels>
            {/* Static Analysis Tab */}
            <TabPanel p={0} pt={4}>
              <Text fontSize="xl" fontWeight="bold" mb={4}>
                Upload File for Static Analysis
              </Text>

              {error && (
                <Alert status="error" borderRadius="md" mb={4}>
                  <AlertIcon />
                  <AlertTitle mr={2}>Error!</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                  <CloseButton
                    position="absolute"
                    right="8px"
                    top="8px"
                    onClick={() => setError(null)}
                  />
                </Alert>
              )}

              <Box
                border="2px dashed"
                borderColor="gray.300"
                borderRadius="md"
                p={10}
                textAlign="center"
                bg="gray.50"
                onDragOver={handleDragOver}
                onDrop={(e) => handleDrop(e, false)}
                onClick={() => fileInputRef.current.click()}
                cursor="pointer"
                _hover={{ borderColor: "brand.400", bg: "gray.100" }}
                mb={4}
              >
                <Input
                  type="file"
                  accept=".exe,.pdf"
                  onChange={(e) => handleFileChange(e, false)}
                  ref={fileInputRef}
                  display="none"
                />

                <Icon
                  as={AttachmentIcon}
                  w={10}
                  h={10}
                  color="gray.400"
                  mb={4}
                />

                <Text fontSize="lg" mb={2}>
                  {file
                    ? file.name
                    : "Drag and drop your file here or click to browse"}
                </Text>

                {file ? (
                  <Text color="gray.500">
                    {(file.size / (1024 * 1024)).toFixed(2)} MB
                  </Text>
                ) : (
                  <Box>
                    <Text color="gray.500">
                      Supported file types: .exe, .pdf
                    </Text>
                    <Text color="gray.500">Maximum file size: 50MB</Text>
                  </Box>
                )}
              </Box>

              <FormControl mb={4}>
                <FormLabel>Analysis Type</FormLabel>
                <RadioGroup onChange={setAnalysisType} value={analysisType}>
                  <Stack direction="row">
                    <Radio value="full">Full Analysis</Radio>
                    <Radio value="static">Static Only</Radio>
                  </Stack>
                </RadioGroup>
              </FormControl>
            </TabPanel>

            {/* Dynamic Analysis Tab */}
            <TabPanel p={0} pt={4}>
              <Text fontSize="xl" fontWeight="bold" mb={4}>
                Upload File for Dynamic Analysis
              </Text>

              <Alert status="warning" borderRadius="md" mb={4}>
                <AlertIcon />
                <Box>
                  <AlertTitle>Caution: Dynamic Analysis</AlertTitle>
                  <AlertDescription>
                    Dynamic analysis will execute the file in a controlled
                    environment. This feature is only available for EXE files.
                  </AlertDescription>
                </Box>
              </Alert>

              {error && (
                <Alert status="error" borderRadius="md" mb={4}>
                  <AlertIcon />
                  <AlertTitle mr={2}>Error!</AlertTitle>
                  <AlertDescription>{error}</AlertDescription>
                  <CloseButton
                    position="absolute"
                    right="8px"
                    top="8px"
                    onClick={() => setError(null)}
                  />
                </Alert>
              )}

              <Box
                border="2px dashed"
                borderColor="orange.300"
                borderRadius="md"
                p={10}
                textAlign="center"
                bg="orange.50"
                onDragOver={handleDragOver}
                onDrop={(e) => handleDrop(e, true)}
                onClick={() => dynamicFileInputRef.current.click()}
                cursor="pointer"
                _hover={{ borderColor: "orange.400", bg: "orange.100" }}
                mb={4}
              >
                <Input
                  type="file"
                  accept=".exe"
                  onChange={(e) => handleFileChange(e, true)}
                  ref={dynamicFileInputRef}
                  display="none"
                />

                <Icon as={FaPlay} w={10} h={10} color="orange.400" mb={4} />

                <Text fontSize="lg" mb={2}>
                  {file
                    ? file.name
                    : "Drag and drop your EXE file here or click to browse"}
                </Text>

                {file ? (
                  <Text color="gray.500">
                    {(file.size / (1024 * 1024)).toFixed(2)} MB
                  </Text>
                ) : (
                  <Box>
                    <Text color="gray.500">Supported file type: .exe only</Text>
                    <Text color="gray.500">Maximum file size: 50MB</Text>
                  </Box>
                )}
              </Box>
            </TabPanel>
          </TabPanels>
        </Tabs>

        {isUploading && (
          <Box>
            <Text mb={2}>Uploading: {uploadProgress}%</Text>
            <Progress
              value={uploadProgress}
              colorScheme="brand"
              size="sm"
              borderRadius="md"
            />
          </Box>
        )}

        <Flex justify="center">
          <Button
            colorScheme={activeTab === 0 ? "brand" : "orange"}
            size="lg"
            onClick={handleUpload}
            isLoading={isUploading}
            loadingText="Uploading"
            isDisabled={!file || isUploading}
            leftIcon={
              activeTab === 0 ? <AttachmentIcon /> : <Icon as={FaPlay} />
            }
            width="full"
          >
            {file
              ? activeTab === 0
                ? "Analyze File"
                : "Run Dynamic Analysis"
              : "Select a File"}
          </Button>
        </Flex>

        <Box>
          <Alert status="warning" variant="subtle" borderRadius="md">
            <AlertIcon as={WarningIcon} />
            <Box>
              <AlertTitle>Caution!</AlertTitle>
              <AlertDescription>
                Only upload files you trust or want to analyze. All uploaded
                files will be scanned for malware.{" "}
                {activeTab === 1 &&
                  "Dynamic analysis will execute the file in a controlled environment."}{" "}
                Do not upload sensitive or personal information.
              </AlertDescription>
            </Box>
          </Alert>
        </Box>
      </VStack>
    </Box>
  );
};

export default FileUpload;

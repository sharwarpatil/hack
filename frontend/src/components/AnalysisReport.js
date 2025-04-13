import React, { useState } from "react";
import {
  Box,
  Heading,
  Text,
  Badge,
  Flex,
  Divider,
  Button,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  SimpleGrid,
  Stat,
  StatLabel,
  StatNumber,
  StatHelpText,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  TableContainer,
  Link,
  Alert,
  AlertIcon,
  Code,
  Progress,
  useColorModeValue,
  Icon,
  Tag,
  TagLabel,
  TagLeftIcon,
  Stack,
  Tabs,
  TabList,
  TabPanels,
  Tab,
  TabPanel,
  useToast,
} from "@chakra-ui/react";

import { useNavigate } from "react-router-dom";
import {
  DownloadIcon,
  WarningTwoIcon,
  CheckCircleIcon,
  InfoIcon,
  TimeIcon,
} from "@chakra-ui/icons";
import { FaPlay } from "react-icons/fa";
import { requestDynamicAnalysis } from "../utils/api";

const severityColors = {
  high: "red",
  medium: "orange",
  low: "blue",
  clean: "green",
  unknown: "gray",
};

const StatusBadge = ({ status }) => {
  let color;
  let icon;

  switch (status) {
    case "completed":
      color = "green";
      icon = CheckCircleIcon;
      break;
    case "processing":
      color = "blue";
      icon = TimeIcon;
      break;
    case "queued":
      color = "yellow";
      icon = TimeIcon;
      break;
    case "failed":
      color = "red";
      icon = WarningTwoIcon;
      break;
    default:
      color = "gray";
      icon = InfoIcon;
  }

  return (
    <Tag size="lg" colorScheme={color} borderRadius="full">
      <TagLeftIcon as={icon} />
      <TagLabel>{status.charAt(0).toUpperCase() + status.slice(1)}</TagLabel>
    </Tag>
  );
};

const AnalysisReport = ({ analysis, status, taskId }) => {
  const navigate = useNavigate();
  const toast = useToast();
  const [activeTab, setActiveTab] = useState(0);
  const bg = useColorModeValue("white", "gray.800");
  const borderColor = useColorModeValue("gray.200", "gray.700");
  const [isDynamicAnalysisRequested, setIsDynamicAnalysisRequested] =
    useState(false);
  const [dynamicAnalysisTaskId, setDynamicAnalysisTaskId] = useState(null);

  if (!analysis && status !== "completed") {
    // Show loading/status screen
    return (
      <Box p={5} shadow="md" borderWidth="1px" borderRadius="lg" bg={bg}>
        <Flex direction="column" align="center" justify="center" py={10}>
          <StatusBadge status={status} />

          <Box mt={6} textAlign="center">
            <Heading size="md" mb={4}>
              Analysis {status}
            </Heading>
            <Text mb={6}>Task ID: {taskId}</Text>

            {status === "processing" && (
              <Box w="100%" maxW="500px" mx="auto">
                <Text mb={2}>Analysis in progress</Text>
                <Progress
                  size="lg"
                  isIndeterminate
                  colorScheme="blue"
                  borderRadius="md"
                />
              </Box>
            )}

            {status === "failed" && (
              <Alert status="error" borderRadius="md" maxW="500px" mx="auto">
                <AlertIcon />
                Analysis failed. Please try uploading the file again.
              </Alert>
            )}
          </Box>
        </Flex>
      </Box>
    );
  }

  if (!analysis) {
    return (
      <Box p={5} shadow="md" borderWidth="1px" borderRadius="lg" bg={bg}>
        <Alert status="error" borderRadius="md">
          <AlertIcon />
          Analysis result not available. Please try again later.
        </Alert>
      </Box>
    );
  }

  const {
    file_info,
    malware_score,
    malware_category,
    severity,
    confidence,
    analysis_time,
    indicators = [],
    exe_details = null,
    pdf_details = null,
    static_analysis_summary,
    malware_family,
    recommendation,
    dynamic_analysis = null,
  } = analysis;

  // Get file type from the analysis data
  const file_type = file_info?.file_type || "";

  const handleRequestDynamicAnalysis = async () => {
    try {
      setIsDynamicAnalysisRequested(true);
      const response = await requestDynamicAnalysis(file_info.file_id);
      setDynamicAnalysisTaskId(response.task_id);

      // Redirect to the analysis page with the new task ID
      navigate(`/analysis/${response.task_id}`);

      toast({
        title: "Dynamic Analysis Requested",
        description:
          "The file is being analyzed. You'll be redirected to view the results.",
        status: "info",
        duration: 5000,
        isClosable: true,
      });
    } catch (error) {
      console.error("Error requesting dynamic analysis:", error);
      toast({
        title: "Error",
        description: "Failed to request dynamic analysis. Please try again.",
        status: "error",
        duration: 5000,
        isClosable: true,
      });
      setIsDynamicAnalysisRequested(false);
    }
  };

  const getScoreColor = (score) => {
    if (score < 0.2) return "green";
    if (score < 0.5) return "blue";
    if (score < 0.8) return "orange";
    return "red";
  };

  const formatFileSize = (bytes) => {
    if (bytes < 1024) return bytes + " B";
    else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + " KB";
    else return (bytes / 1048576).toFixed(2) + " MB";
  };

  return (
    <Box
      p={5}
      shadow="md"
      borderWidth="1px"
      borderRadius="lg"
      bg={bg}
      borderColor={borderColor}
    >
      {/* Header with verdict */}
      <Flex
        justifyContent="space-between"
        alignItems="flex-start"
        direction={{ base: "column", md: "row" }}
        mb={4}
      >
        <Box mb={{ base: 4, md: 0 }}>
          <Heading size="lg" mb={2}>
            Analysis Report
          </Heading>
          <Text color="gray.500">Task ID: {taskId}</Text>
          <Text color="gray.500">
            Analyzed: {new Date(analysis_time).toLocaleString()}
          </Text>
        </Box>

        <Box>
          {file_type === "exe" && !dynamic_analysis && (
            <Button
              leftIcon={<Icon as={FaPlay} />}
              colorScheme="orange"
              onClick={handleRequestDynamicAnalysis}
              isLoading={isDynamicAnalysisRequested}
              loadingText="Requesting..."
              size="sm"
              mr={2}
            >
              Run Dynamic Analysis
            </Button>
          )}

          <Button
            as="a"
            href={`/api/reports/${taskId}`}
            target="_blank"
            rightIcon={<DownloadIcon />}
            colorScheme="brand"
            variant="outline"
            size="sm"
            mb={{ base: 2, md: 0 }}
            mr={2}
          >
            Download PDF
          </Button>

          <Button
            as="a"
            href={`/api/reports/${taskId}?format=json`}
            target="_blank"
            rightIcon={<DownloadIcon />}
            colorScheme="brand"
            variant="outline"
            size="sm"
          >
            Download JSON
          </Button>
        </Box>
      </Flex>

      {/* Verdict */}
      <Box p={4} borderRadius="md" mb={6}>
        <Flex
          direction={{ base: "column", md: "row" }}
          justify="space-between"
          align={{ base: "flex-start", md: "center" }}
        >
          <Box mb={{ base: 2, md: 0 }}>
            <Heading size="md" mb={1}>
              <Badge
                colorScheme={severityColors[severity]}
                fontSize="0.8em"
                p={1}
                borderRadius="md"
              >
                {severity.toUpperCase()} RISK
              </Badge>{" "}
              {malware_category !== "clean"
                ? malware_category
                : "No Threats Detected"}
            </Heading>

            {malware_family && (
              <Text fontWeight="medium">Malware Family: {malware_family}</Text>
            )}
          </Box>

          <Stat textAlign={{ base: "left", md: "right" }} minW="150px">
            <StatLabel>Malware Score</StatLabel>
            <StatNumber color={`${getScoreColor(malware_score)}.500`}>
              {(malware_score * 100).toFixed(1)}%
            </StatNumber>
            <StatHelpText>
              Confidence: {(confidence * 100).toFixed(1)}%
            </StatHelpText>
          </Stat>
        </Flex>
      </Box>

      {/* Summary */}
      <Box mb={6}>
        <Heading size="md" mb={2}>
          Analysis Summary
        </Heading>
        <Text>{static_analysis_summary}</Text>

        {recommendation && (
          <Alert status="info" mt={3} borderRadius="md">
            <AlertIcon />
            <Box>
              <Text fontWeight="bold">Recommendation:</Text>
              <Text>{recommendation}</Text>
            </Box>
          </Alert>
        )}
      </Box>

      {/* Tabs for different sections */}
      <Tabs
        isFitted
        variant="enclosed"
        colorScheme="brand"
        onChange={(index) => setActiveTab(index)}
        index={activeTab}
      >
        <TabList mb="1em">
          <Tab>File Info</Tab>
          <Tab>Indicators ({indicators.length})</Tab>
          {exe_details && <Tab>EXE Analysis</Tab>}
          {pdf_details && <Tab>PDF Analysis</Tab>}
          {dynamic_analysis && <Tab>Dynamic Analysis</Tab>}
        </TabList>

        <TabPanels>
          {/* File Info Panel */}
          <TabPanel>
            <SimpleGrid columns={{ base: 1, md: 2 }} spacing={5}>
              <Stat>
                <StatLabel>File Name</StatLabel>
                <StatNumber fontSize="lg">
                  {file_info.original_filename}
                </StatNumber>
              </Stat>

              <Stat>
                <StatLabel>File Type</StatLabel>
                <StatNumber fontSize="lg">{file_info.file_type}</StatNumber>
                <StatHelpText>{file_info.mime_type}</StatHelpText>
              </Stat>

              <Stat>
                <StatLabel>File Size</StatLabel>
                <StatNumber fontSize="lg">
                  {formatFileSize(file_info.file_size)}
                </StatNumber>
              </Stat>

              <Stat>
                <StatLabel>Upload Time</StatLabel>
                <StatNumber fontSize="lg">
                  {new Date(file_info.upload_time).toLocaleString()}
                </StatNumber>
              </Stat>
            </SimpleGrid>

            <Divider my={4} />

            <Heading size="sm" mb={2}>
              File Hashes
            </Heading>
            <TableContainer>
              <Table variant="simple" size="sm">
                <Tbody>
                  <Tr>
                    <Th>MD5</Th>
                    <Td>
                      <Code>{file_info.md5}</Code>
                    </Td>
                  </Tr>
                  <Tr>
                    <Th>SHA1</Th>
                    <Td>
                      <Code>{file_info.sha1}</Code>
                    </Td>
                  </Tr>
                  <Tr>
                    <Th>SHA256</Th>
                    <Td>
                      <Code>{file_info.sha256}</Code>
                    </Td>
                  </Tr>
                </Tbody>
              </Table>
            </TableContainer>
          </TabPanel>

          {/* Indicators Panel */}
          <TabPanel>
            {indicators.length > 0 ? (
              <TableContainer>
                <Table variant="simple">
                  <Thead>
                    <Tr>
                      <Th>Type</Th>
                      <Th>Name</Th>
                      <Th>Description</Th>
                      <Th>Severity</Th>
                    </Tr>
                  </Thead>
                  <Tbody>
                    {indicators.map((indicator, idx) => (
                      <Tr key={idx}>
                        <Td>{indicator.type}</Td>
                        <Td fontWeight="medium">{indicator.name}</Td>
                        <Td>{indicator.description}</Td>
                        <Td>
                          <Badge
                            colorScheme={severityColors[indicator.severity]}
                          >
                            {indicator.severity}
                          </Badge>
                        </Td>
                      </Tr>
                    ))}
                  </Tbody>
                </Table>
              </TableContainer>
            ) : (
              <Alert status="info" borderRadius="md">
                <AlertIcon />
                No indicators detected.
              </Alert>
            )}
          </TabPanel>

          {/* EXE Analysis Panel */}
          {exe_details && (
            <TabPanel>
              <Accordion allowMultiple defaultIndex={[0]}>
                {/* General Information */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        General Information
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={5}>
                      <Stat>
                        <StatLabel>Architecture</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.architecture || "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Subsystem</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.subsystem || "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Is Packed</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.is_packed ? "Yes" : "No"}
                        </StatNumber>
                        {exe_details.is_packed && (
                          <StatHelpText>
                            Packer: {exe_details.packer_type || "Unknown"}
                          </StatHelpText>
                        )}
                      </Stat>

                      <Stat>
                        <StatLabel>Compile Time</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.compile_time
                            ? new Date(
                                exe_details.compile_time
                              ).toLocaleString()
                            : "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Entry Point</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.entry_point || "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Type</StatLabel>
                        <StatNumber fontSize="lg">
                          {exe_details.is_dll
                            ? "DLL"
                            : exe_details.is_driver
                            ? "Driver"
                            : "Executable"}
                        </StatNumber>
                      </Stat>
                    </SimpleGrid>
                  </AccordionPanel>
                </AccordionItem>

                {/* Sections */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Sections (
                        {exe_details.sections ? exe_details.sections.length : 0}
                        )
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {exe_details.sections && exe_details.sections.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Name</Th>
                              <Th>Virtual Size</Th>
                              <Th>Raw Size</Th>
                              <Th>Entropy</Th>
                              <Th>Characteristics</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {exe_details.sections.map((section, idx) => (
                              <Tr key={idx}>
                                <Td fontFamily="mono">{section.name}</Td>
                                <Td>{section.virtual_size || "N/A"}</Td>
                                <Td>{section.raw_size || "N/A"}</Td>
                                <Td>
                                  {section.entropy ? (
                                    <Badge
                                      colorScheme={
                                        section.entropy > 7.0
                                          ? "red"
                                          : section.entropy > 6.0
                                          ? "yellow"
                                          : "green"
                                      }
                                    >
                                      {section.entropy.toFixed(2)}
                                    </Badge>
                                  ) : (
                                    "N/A"
                                  )}
                                </Td>
                                <Td>
                                  <Stack
                                    direction="row"
                                    spacing={1}
                                    wrap="wrap"
                                  >
                                    {section.characteristics &&
                                      section.characteristics.map((char, i) => (
                                        <Tag
                                          size="sm"
                                          key={i}
                                          colorScheme="gray"
                                          mr={1}
                                          mb={1}
                                        >
                                          {char}
                                        </Tag>
                                      ))}
                                  </Stack>
                                </Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No section information available.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Imports and Libraries */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Imports and Libraries
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    <Heading size="sm" mb={2}>
                      Libraries (
                      {exe_details.libraries ? exe_details.libraries.length : 0}
                      )
                    </Heading>
                    {exe_details.libraries &&
                    exe_details.libraries.length > 0 ? (
                      <Flex wrap="wrap" mb={4}>
                        {exe_details.libraries.map((lib, idx) => (
                          <Tag size="md" key={idx} m={1} colorScheme="blue">
                            {lib}
                          </Tag>
                        ))}
                      </Flex>
                    ) : (
                      <Text mb={4}>No imported libraries detected.</Text>
                    )}

                    <Heading size="sm" mb={2}>
                      Imports (
                      {exe_details.imports ? exe_details.imports.length : 0})
                    </Heading>
                    {exe_details.imports && exe_details.imports.length > 0 ? (
                      <Box
                        maxH="300px"
                        overflowY="auto"
                        borderWidth="1px"
                        borderRadius="md"
                        p={2}
                      >
                        <Code as="pre" overflowX="auto" width="100%">
                          {exe_details.imports.join("\n")}
                        </Code>
                      </Box>
                    ) : (
                      <Text>No imports detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Strings of Interest */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Strings of Interest
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {exe_details.strings_of_interest &&
                    exe_details.strings_of_interest.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Type</Th>
                              <Th>Value</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {exe_details.strings_of_interest.map((str, idx) => (
                              <Tr key={idx}>
                                <Td>{str.type}</Td>
                                <Td>
                                  <Code>{str.value}</Code>
                                </Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No interesting strings detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Resources */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Resources
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {exe_details.resources &&
                    exe_details.resources.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Type</Th>
                              <Th>ID</Th>
                              <Th>Language</Th>
                              <Th>Size</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {exe_details.resources.map((res, idx) => (
                              <Tr key={idx}>
                                <Td>{res.type}</Td>
                                <Td>{res.id}</Td>
                                <Td>{res.language}</Td>
                                <Td>{formatFileSize(res.size)}</Td>
                              </Tr>
                            ))}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No resources detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>
              </Accordion>
            </TabPanel>
          )}

          {/* PDF Analysis Panel */}
          {pdf_details && (
            <TabPanel>
              <Accordion allowMultiple defaultIndex={[0]}>
                {/* General Information */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        General Information
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={5}>
                      <Stat>
                        <StatLabel>PDF Version</StatLabel>
                        <StatNumber fontSize="lg">
                          {pdf_details.version || "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Page Count</StatLabel>
                        <StatNumber fontSize="lg">
                          {pdf_details.page_count || "Unknown"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Contains JavaScript</StatLabel>
                        <StatNumber
                          fontSize="lg"
                          color={
                            pdf_details.has_javascript ? "red.500" : "green.500"
                          }
                        >
                          {pdf_details.has_javascript ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Contains Forms</StatLabel>
                        <StatNumber fontSize="lg">
                          {pdf_details.has_forms ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Embedded Files</StatLabel>
                        <StatNumber
                          fontSize="lg"
                          color={
                            pdf_details.has_embedded_files
                              ? "red.500"
                              : "green.500"
                          }
                        >
                          {pdf_details.has_embedded_files ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Auto Actions</StatLabel>
                        <StatNumber
                          fontSize="lg"
                          color={
                            pdf_details.has_auto_action
                              ? "red.500"
                              : "green.500"
                          }
                        >
                          {pdf_details.has_auto_action ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Encryption</StatLabel>
                        <StatNumber
                          fontSize="lg"
                          color={
                            pdf_details.has_encryption
                              ? "yellow.500"
                              : "green.500"
                          }
                        >
                          {pdf_details.has_encryption ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Obfuscation</StatLabel>
                        <StatNumber
                          fontSize="lg"
                          color={
                            pdf_details.has_obfuscation
                              ? "red.500"
                              : "green.500"
                          }
                        >
                          {pdf_details.has_obfuscation ? "Yes" : "No"}
                        </StatNumber>
                      </Stat>
                    </SimpleGrid>
                  </AccordionPanel>
                </AccordionItem>

                {/* JavaScript */}
                {pdf_details.has_javascript && (
                  <AccordionItem>
                    <h2>
                      <AccordionButton>
                        <Box flex="1" textAlign="left" fontWeight="medium">
                          JavaScript Code
                        </Box>
                        <AccordionIcon />
                      </AccordionButton>
                    </h2>
                    <AccordionPanel pb={4}>
                      {pdf_details.javascript_code &&
                      pdf_details.javascript_code.length > 0 ? (
                        <Box
                          maxH="500px"
                          overflowY="auto"
                          borderWidth="1px"
                          borderRadius="md"
                          p={2}
                        >
                          <Code as="pre" overflowX="auto" width="100%">
                            {pdf_details.javascript_code.join("\n\n")}
                          </Code>
                        </Box>
                      ) : (
                        <Text>
                          JavaScript detected but code could not be extracted.
                        </Text>
                      )}
                    </AccordionPanel>
                  </AccordionItem>
                )}

                {/* Embedded Files */}
                {pdf_details.has_embedded_files && (
                  <AccordionItem>
                    <h2>
                      <AccordionButton>
                        <Box flex="1" textAlign="left" fontWeight="medium">
                          Embedded Files
                        </Box>
                        <AccordionIcon />
                      </AccordionButton>
                    </h2>
                    <AccordionPanel pb={4}>
                      {pdf_details.embedded_files &&
                      pdf_details.embedded_files.length > 0 ? (
                        <TableContainer>
                          <Table variant="simple" size="sm">
                            <Thead>
                              <Tr>
                                <Th>Filename</Th>
                                <Th>Object ID</Th>
                              </Tr>
                            </Thead>
                            <Tbody>
                              {pdf_details.embedded_files.map((file, idx) => (
                                <Tr key={idx}>
                                  <Td>{file.filename}</Td>
                                  <Td>{file.object_id}</Td>
                                </Tr>
                              ))}
                            </Tbody>
                          </Table>
                        </TableContainer>
                      ) : (
                        <Text>
                          Embedded files detected but details could not be
                          extracted.
                        </Text>
                      )}
                    </AccordionPanel>
                  </AccordionItem>
                )}

                {/* Auto Actions */}
                {pdf_details.has_auto_action && (
                  <AccordionItem>
                    <h2>
                      <AccordionButton>
                        <Box flex="1" textAlign="left" fontWeight="medium">
                          Automatic Actions
                        </Box>
                        <AccordionIcon />
                      </AccordionButton>
                    </h2>
                    <AccordionPanel pb={4}>
                      {pdf_details.auto_actions &&
                      pdf_details.auto_actions.length > 0 ? (
                        <TableContainer>
                          <Table variant="simple" size="sm">
                            <Thead>
                              <Tr>
                                <Th>Type</Th>
                                <Th>Object ID</Th>
                              </Tr>
                            </Thead>
                            <Tbody>
                              {pdf_details.auto_actions.map((action, idx) => (
                                <Tr key={idx}>
                                  <Td>{action.type}</Td>
                                  <Td>{action.object_id}</Td>
                                </Tr>
                              ))}
                            </Tbody>
                          </Table>
                        </TableContainer>
                      ) : (
                        <Text>
                          Auto actions detected but details could not be
                          extracted.
                        </Text>
                      )}
                    </AccordionPanel>
                  </AccordionItem>
                )}

                {/* URLs */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        URLs in Document
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>

                  <AccordionPanel pb={4}>
                    {pdf_details.urls && pdf_details.urls.length > 0 ? (
                      <Box
                        maxH="300px"
                        overflowY="auto"
                        borderWidth="1px"
                        borderRadius="md"
                        p={2}
                      >
                        <Stack spacing={2}>
                          {pdf_details.urls.map((url, idx) => (
                            <Box
                              key={idx}
                              p={2}
                              borderWidth="1px"
                              borderRadius="md"
                            >
                              <Code>{url}</Code>
                            </Box>
                          ))}
                        </Stack>
                      </Box>
                    ) : (
                      <Text>No URLs detected in the document.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Suspicious Objects */}
                {pdf_details.has_suspicious_objects && (
                  <AccordionItem>
                    <h2>
                      <AccordionButton>
                        <Box flex="1" textAlign="left" fontWeight="medium">
                          Suspicious Objects
                        </Box>
                        <AccordionIcon />
                      </AccordionButton>
                    </h2>
                    <AccordionPanel pb={4}>
                      {pdf_details.suspicious_objects &&
                      pdf_details.suspicious_objects.length > 0 ? (
                        <TableContainer>
                          <Table variant="simple" size="sm">
                            <Thead>
                              <Tr>
                                <Th>Type</Th>
                                <Th>Pattern</Th>
                                <Th>Object ID</Th>
                              </Tr>
                            </Thead>
                            <Tbody>
                              {pdf_details.suspicious_objects.map(
                                (obj, idx) => (
                                  <Tr key={idx}>
                                    <Td>{obj.type}</Td>
                                    <Td>
                                      <Code>{obj.pattern}</Code>
                                    </Td>
                                    <Td>{obj.object_id}</Td>
                                  </Tr>
                                )
                              )}
                            </Tbody>
                          </Table>
                        </TableContainer>
                      ) : (
                        <Text>
                          Suspicious objects detected but details could not be
                          extracted.
                        </Text>
                      )}
                    </AccordionPanel>
                  </AccordionItem>
                )}
              </Accordion>
            </TabPanel>
          )}

          {/* Dynamic Analysis Panel */}
          {dynamic_analysis && (
            <TabPanel>
              <Accordion allowMultiple defaultIndex={[0]}>
                {/* Suspicious Behaviors */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Suspicious Behaviors (
                        {dynamic_analysis.suspicious_behaviors?.length || 0})
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {dynamic_analysis.suspicious_behaviors?.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Type</Th>
                              <Th>Description</Th>
                              <Th>Severity</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {dynamic_analysis.suspicious_behaviors.map(
                              (behavior, idx) => (
                                <Tr key={idx}>
                                  <Td>
                                    {behavior.type}/{behavior.subtype}
                                  </Td>
                                  <Td>{behavior.description}</Td>
                                  <Td>
                                    <Badge
                                      colorScheme={
                                        severityColors[behavior.severity]
                                      }
                                    >
                                      {behavior.severity}
                                    </Badge>
                                  </Td>
                                </Tr>
                              )
                            )}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No suspicious behaviors detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Network Activity */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Network Activity (
                        {dynamic_analysis.network_activity?.length || 0})
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {dynamic_analysis.network_activity?.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Local</Th>
                              <Th>Remote</Th>
                              <Th>Status</Th>
                              <Th>Process ID</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {dynamic_analysis.network_activity.map(
                              (conn, idx) => (
                                <Tr key={idx}>
                                  <Td>
                                    {conn.local_address}:{conn.local_port}
                                  </Td>
                                  <Td>
                                    {conn.remote_address
                                      ? `${conn.remote_address}:${conn.remote_port}`
                                      : "N/A"}
                                  </Td>
                                  <Td>{conn.status}</Td>
                                  <Td>{conn.pid || "N/A"}</Td>
                                </Tr>
                              )
                            )}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No network activity detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Process Activity */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Process Activity (
                        {dynamic_analysis.process_activity?.length || 0})
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {dynamic_analysis.process_activity?.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>PID</Th>
                              <Th>Name</Th>
                              <Th>User</Th>
                              <Th>Command Line</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {dynamic_analysis.process_activity.map(
                              (proc, idx) => (
                                <Tr key={idx}>
                                  <Td>{proc.pid}</Td>
                                  <Td>{proc.name}</Td>
                                  <Td>{proc.username || "N/A"}</Td>
                                  <Td>
                                    <Text noOfLines={1}>
                                      {proc.command_line
                                        ? proc.command_line.join(" ")
                                        : "N/A"}
                                    </Text>
                                  </Td>
                                </Tr>
                              )
                            )}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No process activity detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* File System Activity */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        File System Activity (
                        {dynamic_analysis.file_system_activity?.length || 0})
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {dynamic_analysis.file_system_activity?.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Path</Th>
                              <Th>Operation</Th>
                              <Th>Timestamp</Th>
                              <Th>Process ID</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {dynamic_analysis.file_system_activity.map(
                              (file_op, idx) => (
                                <Tr key={idx}>
                                  <Td>
                                    <Code>{file_op.path}</Code>
                                  </Td>
                                  <Td>{file_op.operation}</Td>
                                  <Td>
                                    {file_op.timestamp
                                      ? new Date(
                                          file_op.timestamp
                                        ).toLocaleString()
                                      : "N/A"}
                                  </Td>
                                  <Td>{file_op.process_id || "N/A"}</Td>
                                </Tr>
                              )
                            )}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No file system activity detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Registry Activity */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Registry Activity (
                        {dynamic_analysis.registry_activity?.length || 0})
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    {dynamic_analysis.registry_activity?.length > 0 ? (
                      <TableContainer>
                        <Table variant="simple" size="sm">
                          <Thead>
                            <Tr>
                              <Th>Key</Th>
                              <Th>Operation</Th>
                              <Th>Value</Th>
                              <Th>Process ID</Th>
                            </Tr>
                          </Thead>
                          <Tbody>
                            {dynamic_analysis.registry_activity.map(
                              (reg_op, idx) => (
                                <Tr key={idx}>
                                  <Td>
                                    <Code>{reg_op.key}</Code>
                                  </Td>
                                  <Td>{reg_op.operation}</Td>
                                  <Td>{reg_op.value || "N/A"}</Td>
                                  <Td>{reg_op.process_id || "N/A"}</Td>
                                </Tr>
                              )
                            )}
                          </Tbody>
                        </Table>
                      </TableContainer>
                    ) : (
                      <Text>No registry activity detected.</Text>
                    )}
                  </AccordionPanel>
                </AccordionItem>

                {/* Execution Details */}
                <AccordionItem>
                  <h2>
                    <AccordionButton>
                      <Box flex="1" textAlign="left" fontWeight="medium">
                        Execution Details
                      </Box>
                      <AccordionIcon />
                    </AccordionButton>
                  </h2>
                  <AccordionPanel pb={4}>
                    <SimpleGrid columns={{ base: 1, md: 2 }} spacing={5}>
                      <Stat>
                        <StatLabel>Execution Time</StatLabel>
                        <StatNumber fontSize="lg">
                          {dynamic_analysis.execution_time?.toFixed(2) || "N/A"}{" "}
                          seconds
                        </StatNumber>
                      </Stat>

                      <Stat>
                        <StatLabel>Exit Code</StatLabel>
                        <StatNumber fontSize="lg">
                          {dynamic_analysis.exit_code !== null
                            ? dynamic_analysis.exit_code
                            : "N/A"}
                        </StatNumber>
                      </Stat>
                    </SimpleGrid>
                  </AccordionPanel>
                </AccordionItem>
              </Accordion>
            </TabPanel>
          )}
        </TabPanels>
      </Tabs>
    </Box>
  );
};

export default AnalysisReport;

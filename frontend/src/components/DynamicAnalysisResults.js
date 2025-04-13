// DynamicAnalysisResults.js
import React from "react";
import {
  Box,
  Heading,
  Text,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  Badge,
  Accordion,
  AccordionItem,
  AccordionButton,
  AccordionPanel,
  AccordionIcon,
  TableContainer,
  Stack,
} from "@chakra-ui/react";

const severityColors = {
  high: "red",
  medium: "orange",
  low: "blue",
  clean: "green",
  unknown: "gray",
};

const DynamicAnalysisResults = ({ dynamicAnalysis }) => {
  if (!dynamicAnalysis) {
    return (
      <Box textAlign="center" py={10}>
        <Text fontSize="lg">No dynamic analysis data available.</Text>
      </Box>
    );
  }

  return (
    <Box>
      <Heading size="md" mb={4}>
        Dynamic Analysis Results
      </Heading>

      <Accordion allowMultiple defaultIndex={[0]}>
        {/* Suspicious Behaviors */}
        <AccordionItem>
          <h2>
            <AccordionButton>
              <Box flex="1" textAlign="left" fontWeight="medium">
                Suspicious Behaviors (
                {dynamicAnalysis.suspicious_behaviors?.length || 0})
              </Box>
              <AccordionIcon />
            </AccordionButton>
          </h2>
          <AccordionPanel pb={4}>
            {dynamicAnalysis.suspicious_behaviors?.length > 0 ? (
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
                    {dynamicAnalysis.suspicious_behaviors.map(
                      (behavior, idx) => (
                        <Tr key={idx}>
                          <Td>
                            {behavior.type}/{behavior.subtype}
                          </Td>
                          <Td>{behavior.description}</Td>
                          <Td>
                            <Badge
                              colorScheme={severityColors[behavior.severity]}
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
                {dynamicAnalysis.network_activity?.length || 0})
              </Box>
              <AccordionIcon />
            </AccordionButton>
          </h2>
          <AccordionPanel pb={4}>
            {dynamicAnalysis.network_activity?.length > 0 ? (
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
                    {dynamicAnalysis.network_activity.map((conn, idx) => (
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
                    ))}
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
                {dynamicAnalysis.process_activity?.length || 0})
              </Box>
              <AccordionIcon />
            </AccordionButton>
          </h2>
          <AccordionPanel pb={4}>
            {dynamicAnalysis.process_activity?.length > 0 ? (
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
                    {dynamicAnalysis.process_activity.map((proc, idx) => (
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
                    ))}
                  </Tbody>
                </Table>
              </TableContainer>
            ) : (
              <Text>No process activity detected.</Text>
            )}
          </AccordionPanel>
        </AccordionItem>

        {/* Add similar accordions for file system and registry activity */}
      </Accordion>
    </Box>
  );
};

export default DynamicAnalysisResults;
